"""SQLite schema, connection policy, and durable collector state."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
import sqlite3
import time

DB = os.environ.get('DB_FILE', 'db.sqlite')
SCHEMA_VERSION = 5


class EventIdConflictError(ValueError):
    """An event ID was reused for a different normalized event."""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


@contextmanager
def connect(db_file=None):
    connection = sqlite3.connect(db_file or DB, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys = ON')
    connection.execute('PRAGMA busy_timeout = 10000')
    try:
        yield connection
    finally:
        connection.close()


def _enable_wal(connection):
    deadline = time.monotonic() + 10
    delay = 0.01
    while True:
        try:
            mode = connection.execute('PRAGMA journal_mode = WAL').fetchone()[0]
            if mode.lower() != 'wal':
                raise RuntimeError(f'Unable to enable SQLite WAL mode: {mode}')
            return
        except sqlite3.OperationalError as exc:
            if 'locked' not in str(exc).lower() or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.25)


def init_db(db_file=None):
    """Create or upgrade the schema in one transaction; safe to call repeatedly."""
    with connect(db_file) as connection:
        _enable_wal(connection)
        connection.execute('PRAGMA synchronous = FULL')
        connection.execute('BEGIN IMMEDIATE')
        try:
            version = connection.execute('PRAGMA user_version').fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f'Database schema {version} is newer than supported {SCHEMA_VERSION}')

            connection.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                    event_time TEXT NOT NULL,
                    ingestion_time TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    host TEXT,
                    user_name TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER CHECK (src_port IS NULL OR src_port BETWEEN 1 AND 65535),
                    dst_port INTEGER CHECK (dst_port IS NULL OR dst_port BETWEEN 1 AND 65535),
                    event_type TEXT NOT NULL,
                    action TEXT,
                    outcome TEXT,
                    process TEXT,
                    command_line TEXT,
                    domain TEXT,
                    url TEXT,
                    file_hash TEXT,
                    metadata_json TEXT NOT NULL
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK (severity IN ('HIGH', 'MEDIUM', 'LOW')),
                    details TEXT NOT NULL,
                    event_id TEXT REFERENCES events(event_id) ON DELETE SET NULL
                )
            ''')
            # -- SOC-core alert columns (schema v2) --------------------------
            # Kept NULL-tolerant so Phase 1 rows remain valid. Existing alert
            # consumers keep working; new fields appear alongside them.
            alert_columns = {
                row['name'] for row in connection.execute('PRAGMA table_info(alerts)')
            }
            if 'event_id' not in alert_columns:
                connection.execute(
                    'ALTER TABLE alerts ADD COLUMN event_id TEXT REFERENCES events(event_id) ON DELETE SET NULL')
            soc_columns = {
                'detection_id': 'TEXT',
                'rule_id': 'TEXT',
                'deterministic_risk_score': 'INTEGER',
                'risk_band': 'TEXT',
                'risk_factors_json': 'TEXT',
                'risk_explanation': 'TEXT',
                'jev_priority': 'TEXT',
                'jev_malicious_likelihood': 'REAL',
                'jev_false_positive_likelihood': 'REAL',
                'jev_investigation_required': 'INTEGER',
                'jev_attack_category': 'TEXT',
                'jev_status': 'TEXT',
                'mitre_techniques_json': 'TEXT',
                'evidence_json': 'TEXT',
                'source_event_ids_json': 'TEXT',
                'correlation_id': 'TEXT',
                'investigation_status': "TEXT NOT NULL DEFAULT 'new'",
            }
            for column, column_type in soc_columns.items():
                if column not in alert_columns:
                    connection.execute(
                        f'ALTER TABLE alerts ADD COLUMN {column} {column_type}')

            connection.execute('''
                CREATE TABLE IF NOT EXISTS alert_enrichment (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    UNIQUE (alert_id, key)
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS file_cursors (
                    source_path TEXT PRIMARY KEY,
                    file_identity TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation >= 0),
                    byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
                    last_line_hash TEXT,
                    updated_at TEXT NOT NULL
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS ingestion_errors (
                    source_path TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    start_offset INTEGER NOT NULL,
                    end_offset INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL,
                    error TEXT NOT NULL,
                    preview TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    PRIMARY KEY (source_path, generation, start_offset)
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS failed_login_attempts (
                    event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE CASCADE,
                    source_ip TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    user_name TEXT
                )
            ''')
            fla_columns = {
                row['name'] for row in connection.execute(
                    'PRAGMA table_info(failed_login_attempts)')
            }
            if 'user_name' not in fla_columns:
                connection.execute(
                    'ALTER TABLE failed_login_attempts ADD COLUMN user_name TEXT')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS correlations (
                    correlation_id TEXT PRIMARY KEY,
                    key TEXT NOT NULL,
                    primary_rule_id TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS alert_suppression (
                    scope TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    last_alert_time TEXT NOT NULL,
                    PRIMARY KEY (scope, indicator)
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS investigation_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    source TEXT NOT NULL
                )
            ''')
            # -- SOAR framework (schema v4) -----------------------------------
            # Playbook definitions are versioned; executions, actions,
            # approvals, incidents, and audit rows reference them. All SOAR
            # writes go through soar.py, which enforces the state machine and
            # idempotency; nothing else should touch these tables directly.
            connection.execute('''
                CREATE TABLE IF NOT EXISTS soar_playbooks (
                    playbook_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1),
                    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                    definition_json TEXT NOT NULL,
                    definition_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS soar_executions (
                    execution_id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL REFERENCES soar_playbooks(playbook_id),
                    playbook_version INTEGER NOT NULL,
                    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
                    state TEXT NOT NULL CHECK (state IN (
                        'PENDING', 'VALIDATING', 'WAITING_APPROVAL', 'APPROVED',
                        'RUNNING', 'SUCCEEDED', 'VALIDATION_FAILED',
                        'APPROVAL_REJECTED', 'APPROVAL_EXPIRED', 'ACTION_FAILED',
                        'CANCELLED', 'TIMED_OUT')),
                    dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
                    idempotency_key TEXT NOT NULL,
                    trigger_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    evidence_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (idempotency_key)
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS soar_execution_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT NOT NULL REFERENCES soar_executions(execution_id)
                        ON DELETE CASCADE,
                    action_index INTEGER NOT NULL CHECK (action_index >= 0),
                    action_type TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN (
                        'PENDING', 'WAITING_APPROVAL', 'APPROVED', 'RUNNING',
                        'SUCCEEDED', 'FAILED', 'SKIPPED', 'CANCELLED', 'TIMED_OUT')),
                    parameters_json TEXT NOT NULL,
                    dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                    result_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (execution_id, action_index)
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS soar_approvals (
                    approval_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL REFERENCES soar_executions(execution_id)
                        ON DELETE CASCADE,
                    action_index INTEGER NOT NULL,
                    action_type TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    requester TEXT NOT NULL,
                    approver TEXT,
                    decision TEXT NOT NULL CHECK (decision IN (
                        'pending', 'approved', 'rejected', 'expired', 'cancelled')),
                    decided_at TEXT,
                    reason TEXT,
                    expires_at TEXT NOT NULL,
                    required_role TEXT NOT NULL
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS soar_incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN (
                        'open', 'contained', 'resolved', 'closed')),
                    alert_ids_json TEXT NOT NULL,
                    correlation_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (title, correlation_id)
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS soar_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT,
                    playbook_id TEXT,
                    action_index INTEGER,
                    alert_id INTEGER,
                    actor TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    from_state TEXT,
                    to_state TEXT,
                    dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
                    approval_state TEXT,
                    result_json TEXT,
                    failure_reason TEXT,
                    created_at TEXT NOT NULL
                )
            ''')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_soar_executions_playbook '
                'ON soar_executions(playbook_id, created_at DESC)')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_soar_executions_alert '
                'ON soar_executions(alert_id)')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_soar_actions_execution '
                'ON soar_execution_actions(execution_id, action_index)')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_soar_approvals_execution '
                'ON soar_approvals(execution_id)')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_soar_audit_execution '
                'ON soar_audit(execution_id, id)')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_soar_audit_alert '
                'ON soar_audit(alert_id)')
            # -- SOC operations integration (schema v5) ------------------------
            # Simulation runs and persisted AI investigation results. Rows are
            # written only by soc_simulation.py; everything is attributable and
            # removable by the demo reset without touching non-simulation data.
            connection.execute('''
                CREATE TABLE IF NOT EXISTS simulation_runs (
                    run_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('generated', 'processed')),
                    event_count INTEGER NOT NULL CHECK (event_count >= 0),
                    generated_at TEXT NOT NULL,
                    processed_at TEXT,
                    updated_at TEXT,
                    event_ids_json TEXT NOT NULL,
                    validation_json TEXT
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS simulation_events (
                    run_id TEXT NOT NULL REFERENCES simulation_runs(run_id)
                        ON DELETE CASCADE,
                    event_index INTEGER NOT NULL CHECK (event_index >= 0),
                    event_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE (run_id, event_index)
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS simulation_run_alerts (
                    run_id TEXT NOT NULL REFERENCES simulation_runs(run_id)
                        ON DELETE CASCADE,
                    alert_id INTEGER NOT NULL,
                    UNIQUE (run_id, alert_id)
                )
            ''')
            connection.execute('''
                CREATE TABLE IF NOT EXISTS ai_investigation_results (
                    alert_id INTEGER PRIMARY KEY,
                    ai_schema_version TEXT,
                    status TEXT NOT NULL,
                    response_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_simulation_events_run '
                'ON simulation_events(run_id, event_index)')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_simulation_alerts_run '
                'ON simulation_run_alerts(run_id)')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_alerts_severity '
                'ON alerts(severity, id DESC)')
            connection.execute(
                'CREATE INDEX IF NOT EXISTS idx_alerts_investigation_status '
                'ON alerts(investigation_status, id DESC)')
            # Phase 2 lifecycle values canonicalize to the Phase 3 states.
            if version < 3:
                connection.execute(
                    "UPDATE alerts SET investigation_status = 'investigating' "
                    "WHERE investigation_status = 'in_progress'")
                connection.execute(
                    "UPDATE alerts SET investigation_status = 'resolved' "
                    "WHERE investigation_status = 'closed'")
            connection.execute('CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id, id DESC)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_alerts_correlation ON alerts(correlation_id)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_correlations_key ON correlations(key)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_investigation_events_alert ON investigation_events(alert_id)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(time DESC, id DESC)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule, id DESC)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_events_time_type ON events(event_time, event_type)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_events_source_ip_time ON events(src_ip, event_time)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_enrichment_alert ON alert_enrichment(alert_id)')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_failed_login_window ON failed_login_attempts(source_ip, event_time)')
            connection.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def get_file_cursor(source_path, db_file=None):
    with connect(db_file) as connection:
        row = connection.execute(
            'SELECT source_path, file_identity, generation, byte_offset, last_line_hash '
            'FROM file_cursors WHERE source_path = ?', (source_path,)).fetchone()
        return dict(row) if row else None


def _save_file_cursor(connection, cursor):
    connection.execute('''
        INSERT INTO file_cursors
            (source_path, file_identity, generation, byte_offset, last_line_hash, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_path) DO UPDATE SET
            file_identity = excluded.file_identity,
            generation = excluded.generation,
            byte_offset = excluded.byte_offset,
            last_line_hash = excluded.last_line_hash,
            updated_at = excluded.updated_at
    ''', (
        cursor['source_path'], cursor['file_identity'], cursor['generation'],
        cursor['byte_offset'], cursor.get('last_line_hash'), utc_now(),
    ))


def save_file_cursor(cursor, db_file=None):
    with connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            _save_file_cursor(connection, cursor)
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def record_ingestion_error(record, error, db_file=None):
    raw = record.raw
    with connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            connection.execute('''
                INSERT OR IGNORE INTO ingestion_errors
                    (source_path, generation, start_offset, end_offset, recorded_at,
                     error, preview, content_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                record.source_path, record.generation, record.start_offset,
                record.end_offset, utc_now(), str(error)[:512],
                raw[:256].decode('utf-8', errors='replace'),
                record.content_sha256 or hashlib.sha256(raw).hexdigest(),
            ))
            _save_file_cursor(connection, {
                'source_path': record.source_path,
                'file_identity': record.file_identity,
                'generation': record.generation,
                'byte_offset': record.end_offset,
                'last_line_hash': record.line_hash,
            })
            connection.commit()
        except Exception:
            connection.rollback()
            raise
