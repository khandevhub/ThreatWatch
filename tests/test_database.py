"""Authoritative SQLite initialization and migration tests."""
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import subprocess
import sys

from database import SCHEMA_VERSION, init_db


def test_initialization_is_repeatable_and_adds_constraints_and_indexes(tmp_path):
    dbfile = tmp_path / 'new.sqlite'
    init_db(str(dbfile))
    init_db(str(dbfile))

    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert {'events', 'alerts', 'alert_enrichment', 'file_cursors',
                'ingestion_errors', 'failed_login_attempts'} <= tables
        indexes = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index'")}
        assert 'idx_alerts_time' in indexes
        assert 'idx_failed_login_window' in indexes
        foreign_keys = connection.execute('PRAGMA foreign_key_list(alert_enrichment)').fetchall()
        assert any(row[2] == 'alerts' for row in foreign_keys)


def test_legacy_alert_database_is_migrated_without_losing_rows(tmp_path):
    dbfile = tmp_path / 'legacy.sqlite'
    with sqlite3.connect(str(dbfile)) as connection:
        connection.execute('''CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT, rule TEXT, severity TEXT, details TEXT)''')
        connection.execute('''CREATE TABLE alert_enrichment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL)''')
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details) VALUES (?, ?, ?, ?)",
            ('2025-01-01T00:00:00', 'PORT_SCAN', 'MEDIUM', 'legacy alert'))

    init_db(str(dbfile))
    with sqlite3.connect(str(dbfile)) as connection:
        row = connection.execute(
            'SELECT id, rule, details, event_id FROM alerts').fetchone()
        assert row == (1, 'PORT_SCAN', 'legacy alert', None)
        assert connection.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION


def test_concurrent_initialization_is_safe(tmp_path):
    dbfile = tmp_path / 'concurrent.sqlite'
    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(lambda _: init_db(str(dbfile)), range(4)))
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 0


def test_separate_processes_can_initialize_shared_database(tmp_path):
    dbfile = tmp_path / 'processes.sqlite'
    code = 'from database import init_db; import sys; init_db(sys.argv[1])'
    command = [sys.executable, '-B', '-c', code, str(dbfile)]
    with ThreadPoolExecutor(max_workers=3) as workers:
        results = list(workers.map(
            lambda _: subprocess.run(command, capture_output=True, text=True), range(3)))
    assert [result.returncode for result in results] == [0, 0, 0], [
        result.stderr for result in results]
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION
