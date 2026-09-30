"""Durable JSONL collector with restart-safe byte cursors."""
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import threading
import time

from database import DB, get_file_cursor, init_db, record_ingestion_error, save_file_cursor
from detector import process_event
from event_model import EventValidationError, SecurityEvent
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

SIM_FILE = os.environ.get('SIM_FILE', 'simulated_logs.jsonl')
MAX_LINE_BYTES = 1024 * 1024
BATCH_SIZE = 32

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('collector')


def _norm(path):
    return os.path.normcase(os.path.normpath(path))


def _path_matches(event_path, watched):
    ev, wt = _norm(event_path), _norm(watched)
    if ev == wt or ev.endswith(wt):
        return True
    return _norm(os.path.abspath(event_path)) == _norm(os.path.abspath(watched))


@dataclass(frozen=True)
class TailRecord:
    source_path: str
    file_identity: str
    generation: int
    start_offset: int
    end_offset: int
    raw: bytes
    line_hash: str
    event_id: str
    oversized: bool = False
    content_sha256: str = ''


class TailReader:
    """Read complete lines from the durable cursor, starting at byte zero."""

    def __init__(self, path, db_file=None):
        self.path = os.path.abspath(path)
        self.db_file = db_file or DB
        init_db(self.db_file)
        self._cursor = None
        self._refresh_cursor()

    @staticmethod
    def _identity(stat):
        return f'{stat.st_dev}:{stat.st_ino}'

    def _hash_line_at(self, offset):
        if offset <= 0:
            return None
        start = max(0, offset - MAX_LINE_BYTES - 2)
        with open(self.path, 'rb') as stream:
            stream.seek(start)
            data = stream.read(offset - start)
        line = data[:-1] if data.endswith(b'\n') else data
        if line.endswith(b'\r'):
            line = line[:-1]
        previous_newline = line.rfind(b'\n')
        line = line[previous_newline + 1:][-MAX_LINE_BYTES:]
        return hashlib.sha256(line).hexdigest()

    def _read_record(self, stream):
        start = stream.tell()
        preview = bytearray()
        tail = bytearray()
        digest = hashlib.sha256()
        total = 0
        terminated = False
        while True:
            chunk = stream.readline(64 * 1024)
            if not chunk:
                if total <= MAX_LINE_BYTES:
                    stream.seek(start)
                    return None
                break
            total += len(chunk)
            digest.update(chunk)
            if len(preview) < MAX_LINE_BYTES + 2:
                preview.extend(chunk[:MAX_LINE_BYTES + 2 - len(preview)])
            tail.extend(chunk)
            if len(tail) > MAX_LINE_BYTES + 2:
                del tail[:-MAX_LINE_BYTES - 2]
            if chunk.endswith(b'\n'):
                terminated = True
                break

        content_length = total - (1 if terminated else 0)
        oversized = content_length > MAX_LINE_BYTES
        raw = bytes(preview)
        if terminated and raw.endswith(b'\n'):
            raw = raw[:-1]
        if terminated and raw.endswith(b'\r'):
            raw = raw[:-1]
        if oversized:
            raw = raw[:MAX_LINE_BYTES]

        hashed_line = bytes(tail)
        if terminated and hashed_line.endswith(b'\n'):
            hashed_line = hashed_line[:-1]
        if terminated and hashed_line.endswith(b'\r'):
            hashed_line = hashed_line[:-1]
        line_hash = hashlib.sha256(hashed_line[-MAX_LINE_BYTES:]).hexdigest()
        identity = self._cursor['file_identity']
        generation = self._cursor['generation']
        event_id = 'file:' + hashlib.sha256(
            f'{self.path}\0{identity}\0{generation}\0{start}'.encode('utf-8')
        ).hexdigest()
        return TailRecord(
            source_path=self.path,
            file_identity=identity,
            generation=generation,
            start_offset=start,
            end_offset=stream.tell(),
            raw=raw,
            line_hash=line_hash,
            event_id=event_id,
            oversized=oversized,
            content_sha256=digest.hexdigest(),
        )

    def _refresh_cursor(self):
        try:
            stat = os.stat(self.path)
        except OSError:
            self._cursor = None
            return

        identity = self._identity(stat)
        cursor = get_file_cursor(self.path, self.db_file)
        if cursor is None:
            cursor = {
                'source_path': self.path,
                'file_identity': identity,
                'generation': 0,
                'byte_offset': 0,
                'last_line_hash': None,
            }
            save_file_cursor(cursor, self.db_file)
        else:
            offset = cursor['byte_offset']
            changed = cursor['file_identity'] != identity or stat.st_size < offset
            if not changed and offset and cursor['last_line_hash']:
                changed = self._hash_line_at(offset) != cursor['last_line_hash']
            if changed:
                cursor = {
                    'source_path': self.path,
                    'file_identity': identity,
                    'generation': cursor['generation'] + 1,
                    'byte_offset': 0,
                    'last_line_hash': None,
                }
                save_file_cursor(cursor, self.db_file)
        self._cursor = cursor

    def read_new_lines(self, max_lines=BATCH_SIZE):
        """Return bounded batches of complete, unacknowledged lines."""
        self._refresh_cursor()
        if self._cursor is None or max_lines < 1:
            return []
        out = []
        try:
            with open(self.path, 'rb') as stream:
                stream.seek(self._cursor['byte_offset'])
                while len(out) < max_lines:
                    start = stream.tell()
                    record = self._read_record(stream)
                    if record is None:
                        break
                    if record.end_offset <= start:
                        break
                    out.append(record)
        except OSError as exc:
            logger.warning('Tail read failed for %s: %s', self.path, exc)
        return out

    def acknowledge(self, record):
        """Persist progress only after the event or its rejection is stored."""
        cursor = {
            'source_path': record.source_path,
            'file_identity': record.file_identity,
            'generation': record.generation,
            'byte_offset': record.end_offset,
            'last_line_hash': record.line_hash,
        }
        save_file_cursor(cursor, self.db_file)
        self._cursor = cursor


class SimHandler(FileSystemEventHandler):
    def __init__(self, path, tail=None, db_file=None):
        self.path = os.path.abspath(path)
        self.db_file = db_file or DB
        self.tail = tail or TailReader(self.path, self.db_file)
        self._drain_lock = threading.Lock()

    def _on_path_change(self, path, is_directory=False):
        if not is_directory and _path_matches(path, self.path):
            self.drain()

    def on_modified(self, event):
        self._on_path_change(event.src_path, getattr(event, 'is_directory', False))

    def on_created(self, event):
        self._on_path_change(event.src_path, getattr(event, 'is_directory', False))

    def on_moved(self, event):
        self._on_path_change(getattr(event, 'dest_path', ''), getattr(event, 'is_directory', False))

    def drain(self):
        if not self._drain_lock.acquire(blocking=False):
            return
        try:
            while True:
                records = self.tail.read_new_lines()
                if not records:
                    break
                for record in records:
                    if not record.raw.strip():
                        self.tail.acknowledge(record)
                        continue
                    try:
                        if record.oversized:
                            raise EventValidationError(
                                f'JSONL record exceeds {MAX_LINE_BYTES} bytes')
                        text = record.raw.decode('utf-8')
                        payload = json.loads(text)
                        event = SecurityEvent.from_payload(
                            payload, default_source='jsonl', generated_event_id=record.event_id)
                    except (UnicodeDecodeError, json.JSONDecodeError, EventValidationError) as exc:
                        logger.warning('Quarantining malformed event at %s:%d: %s',
                                       self.path, record.start_offset, exc)
                        record_ingestion_error(record, exc, self.db_file)
                        self.tail.acknowledge(record)
                        continue
                    try:
                        process_event(event, db_file=self.db_file)
                        self.tail.acknowledge(record)
                    except Exception:
                        logger.exception('Event processing failed at %s:%d; cursor retained',
                                         self.path, record.start_offset)
                        return
                if len(records) < BATCH_SIZE:
                    break
        finally:
            self._drain_lock.release()


def run_collector(sim_file=SIM_FILE, db_file=DB):
    init_db(db_file)
    absolute_file = os.path.abspath(sim_file)
    os.makedirs(os.path.dirname(absolute_file), exist_ok=True)
    if not os.path.exists(absolute_file):
        from simulator.catalog import events_jsonl
        with open(absolute_file, 'w', encoding='utf-8', newline='') as stream:
            stream.write(events_jsonl())
        logger.info('Wrote sample simulated file: %s', absolute_file)

    tail = TailReader(absolute_file, db_file)
    event_handler = SimHandler(absolute_file, tail, db_file)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(absolute_file), recursive=False)
    observer.start()
    try:
        event_handler.drain()
        logger.info('Watching %s; append JSONL events to ingest them.', absolute_file)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info('Stopping collector.')
    finally:
        observer.stop()
        observer.join()


if __name__ == '__main__':
    run_collector()
