"""Deterministic demo detections over validated normalized events."""
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from database import DB, EventIdConflictError, connect, init_db
from event_model import SecurityEvent

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('detector')


def _positive_setting(name, default):
    value = int(os.environ.get(name, str(default)))
    if value < 1:
        raise ValueError(f'{name} must be a positive integer')
    return value


DETECTION_WINDOW = _positive_setting('DETECTION_WINDOW', 60)
BRUTE_FORCE_THRESHOLD = _positive_setting('BRUTE_FORCE_THRESHOLD', 5)
THREAT_INTEL = os.environ.get('THREAT_INTEL', 'threat_intel.csv')


def load_threat_intel(path):
    """Load the demonstration IP/tag CSV into an exact-match lookup."""
    table = {}
    if not path or not os.path.exists(path):
        logger.warning('Threat intel file not found: %s', path)
        return table
    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.lower().startswith('ip'):
                continue
            parts = [part.strip() for part in line.split(',')]
            if not parts or not parts[0]:
                continue
            tag = parts[1] if len(parts) > 1 and parts[1] else 'known_threat'
            table[parts[0]] = tag
    return table


bad_ips = load_threat_intel(THREAT_INTEL)


def _insert_alert(connection, event, rule, severity, details, enrichment=None):
    cursor = connection.execute(
        'INSERT INTO alerts (time, rule, severity, details, event_id) VALUES (?, ?, ?, ?, ?)',
        (event.ingestion_time, rule, severity, details, event.event_id),
    )
    alert_id = cursor.lastrowid
    if enrichment:
        connection.executemany(
            'INSERT INTO alert_enrichment (alert_id, key, value) VALUES (?, ?, ?)',
            [(alert_id, key, str(value)) for key, value in enrichment.items()],
        )
    return rule, severity, details


def _event_values(event):
    return (
        event.event_id, event.schema_version, event.event_time, event.ingestion_time,
        event.source, event.source_type, event.host, event.user, event.src_ip,
        event.dst_ip, event.src_port, event.dst_port, event.event_type, event.action,
        event.outcome, event.process, event.command_line, event.domain, event.url,
        event.file_hash, json.dumps(event.metadata, ensure_ascii=False, sort_keys=True),
    )


def _store_event(connection, event):
    cursor = connection.execute('''
        INSERT OR IGNORE INTO events (
            event_id, schema_version, event_time, ingestion_time, source, source_type,
            host, user_name, src_ip, dst_ip, src_port, dst_port, event_type, action,
            outcome, process, command_line, domain, url, file_hash, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', _event_values(event))
    if cursor.rowcount == 1:
        return True

    existing = connection.execute('''
        SELECT schema_version, source, source_type, host, user_name, src_ip, dst_ip,
               src_port, dst_port, event_type, action, outcome, process, command_line,
               domain, url, file_hash, metadata_json
        FROM events WHERE event_id = ?
    ''', (event.event_id,)).fetchone()
    if existing is None:
        raise sqlite3.IntegrityError('Event could not be persisted')
    current = (
        event.schema_version, event.source, event.source_type, event.host, event.user,
        event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.event_type,
        event.action, event.outcome, event.process, event.command_line, event.domain,
        event.url, event.file_hash,
        json.dumps(event.metadata, ensure_ascii=False, sort_keys=True),
    )
    if tuple(existing) != current:
        raise EventIdConflictError('event_id is already associated with different event data')
    return False


def _enrichment(src):
    return {
        'source_ip': src,
        'known_threat': 'true' if src in bad_ips else 'false',
    }


def _detect(connection, event):
    typ = event.event_type
    src = event.src_ip or 'unknown'
    tag = bad_ips.get(src)
    if typ == 'auth_failed':
        cutoff = datetime.fromisoformat(event.event_time.replace('Z', '+00:00')) - timedelta(
            seconds=DETECTION_WINDOW)
        cutoff_text = cutoff.astimezone(timezone.utc).isoformat(
            timespec='microseconds').replace('+00:00', 'Z')
        connection.execute(
            'DELETE FROM failed_login_attempts WHERE event_time <= ?', (cutoff_text,))
        connection.execute(
            'INSERT INTO failed_login_attempts (event_id, source_ip, event_time) VALUES (?, ?, ?)',
            (event.event_id, src, event.event_time),
        )
        count = connection.execute(
            'SELECT COUNT(*) FROM failed_login_attempts WHERE source_ip = ? AND event_time > ?',
            (src, cutoff_text),
        ).fetchone()[0]
        if count >= BRUTE_FORCE_THRESHOLD:
            note = f' [{tag.upper()}]' if tag else ''
            alert = _insert_alert(
                connection, event, 'BRUTE_FORCE', 'HIGH',
                f'Multiple failed logins from {src}: {count} attempts' + note,
                _enrichment(src),
            )
            connection.execute('DELETE FROM failed_login_attempts WHERE source_ip = ?', (src,))
            return alert
    elif typ == 'port_scan':
        ports = event.metadata.get('ports', [])
        note = f' [{tag.upper()}]' if tag else ''
        return _insert_alert(
            connection, event, 'PORT_SCAN', 'MEDIUM',
            f'Port scan detected from {src} - ports: {ports}' + note,
            _enrichment(src),
        )
    elif typ == 'traffic_spike':
        bytes_val = event.metadata.get('bytes', 0)
        note = ' [KNOWN_THREAT]' if tag else ''
        return _insert_alert(
            connection, event, 'TRAFFIC_SPIKE', 'LOW',
            f'High outbound traffic: {bytes_val} bytes' + note,
            _enrichment(src),
        )
    else:
        logger.debug('Unhandled event type: %s', typ)
    return None


def process_event(evt, *, db_file=None, generated_event_id=None):
    """Persist and detect one event atomically; return False for an identical replay."""
    event = evt if isinstance(evt, SecurityEvent) else SecurityEvent.from_payload(
        evt, default_source='simulator', generated_event_id=generated_event_id)
    alert = None
    with connect(db_file or DB) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            if not _store_event(connection, event):
                connection.commit()
                return False
            alert = _detect(connection, event)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    if alert:
        logger.info('[ALERT] %s %s %s', event.ingestion_time, *alert)
    return True


if __name__ == '__main__':
    init_db(DB)
    for _ in range(5):
        process_event({'type': 'auth_failed', 'src': '10.0.0.5'})
    print('Detector self-test complete. Check the alerts table in', DB)
