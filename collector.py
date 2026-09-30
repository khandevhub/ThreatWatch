# collector.py - simulated-log collector with incremental tailing
import os
import time
import json
import logging
from datetime import datetime

from detector import process_event, init_db
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOGFILE_LINUX = os.environ.get('LOG_PATH', '/var/log/auth.log')
SIM_FILE = os.environ.get('SIM_FILE', 'simulated_logs.jsonl')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('collector')


def _norm(path):
    """Normalize a path for comparison (separator- and case-safe on Windows)."""
    return os.path.normcase(os.path.normpath(path))


def _path_matches(event_path, watched):
    """True if event_path refers to the watched file, regardless of whether
    absolute/relative or forward/backward separators were used."""
    ev, wt = _norm(event_path), _norm(watched)
    if ev == wt or ev.endswith(wt):
        return True
    # mixed relative/absolute: resolve both against the current directory
    # (the collector's cwd is the watched directory) and compare again
    return _norm(os.path.abspath(event_path)) == _norm(os.path.abspath(watched))


class TailReader:
    """Incrementally reads appended lines from a text file.

    Remembers the byte offset after the last complete line and, on first
    read of a small pre-existing file, keeps it entirely so the original
    "auto-watch simulated file" convenience is preserved. For large
    pre-existing files it seeks to the end (append-only convention).
    """

    def __init__(self, path, max_initial_read=1 * 1024 * 1024):
        self.path = path
        self._offset = None
        self._mtime_ns = None
        self._last_line = None
        self._max_initial_read = max_initial_read

    def _current_last_line(self):
        """Best-effort read of the file's current final non-empty line."""
        try:
            size = os.path.getsize(self.path)
            with open(self.path, 'rb') as f:
                f.seek(max(0, size - 8192))
                chunk = f.read().decode('utf-8', errors='replace')
            lines = [l for l in chunk.splitlines() if l.strip()]
            return lines[-1] if lines else None
        except OSError:
            return None

    def read_new_lines(self):
        """Return newly appended lines since the last call."""
        try:
            size = os.path.getsize(self.path)
            mtime_ns = os.stat(self.path).st_mtime_ns
        except OSError:
            return []
        if self._offset is None:
            if size <= self._max_initial_read:
                self._offset = 0          # keep small pre-existing file entirely
            else:
                self._offset = size       # seek to end for large pre-existing files
                self._mtime_ns = mtime_ns
                return []
        elif size == self._offset and self._offset > 0 and (
            self._mtime_ns is not None and mtime_ns != self._mtime_ns
        ):
            # Same size but mtime moved: either a harmless metadata touch or a
            # same-length rewrite. Confirm by comparing the file's last line
            # with the last line we processed; mtime alone proved unreliable
            # (Windows fires extra events whose mtime bumps caused duplicate
            # full-file re-reads).
            if self._current_last_line() != self._last_line:
                self._offset = 0          # rewritten in place: start over
        self._mtime_ns = mtime_ns
        out = []
        if size == self._offset:
            return out
        try:
            with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(self._offset)
                while True:
                    pos_before = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith('\n'):
                        # incomplete final line: hold it back until completed
                        f.seek(pos_before)
                        break
                    self._offset = f.tell()
                    out.append(line.rstrip('\n'))
        except OSError as exc:
            logger.warning('Tail read failed: %s', exc)
        if out:
            self._last_line = out[-1]
        return out


class SimHandler(FileSystemEventHandler):
    def __new__(cls, path, tail=None):
        if tail is None:
            tail = TailReader(path)
        return super().__new__(cls)

    def __init__(self, path, tail=None):
        self.path = path
        if tail is None:
            tail = TailReader(path)
        self.tail = tail

    def on_modified(self, event):
        if getattr(event, 'is_directory', False):
            return
        if _path_matches(event.src_path, self.path):
            logger.info('Detected change in simulated logs, processing...')
            self.drain()

    def drain(self):
        lines = self.tail.read_new_lines()
        for line in lines:
            if not line.strip():
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                logger.warning('Skipping malformed JSON line: %r', line[:120])
                continue
            try:
                if 'time' not in evt:
                    evt['time'] = datetime.utcnow().isoformat()
                process_event(evt)
            except Exception:
                logger.exception('Failed to process event line: %r', line[:120])


if __name__ == '__main__':
    init_db()
    if not os.path.exists(SIM_FILE):
        from simulator.catalog import events_jsonl
        with open(SIM_FILE, 'w', encoding='utf-8') as f:
            f.write(events_jsonl())
        logger.info('Wrote sample simulated file: %s', SIM_FILE)
    tail = TailReader(SIM_FILE)
    event_handler = SimHandler(SIM_FILE, tail)
    observer = Observer()
    observer.schedule(event_handler, path='.', recursive=False)
    observer.start()
    logger.info('Watching %s for changes. Append events to this file to trigger processing.', SIM_FILE)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
