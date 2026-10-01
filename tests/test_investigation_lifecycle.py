"""Phase 3H: investigation lifecycle — canonical states, transitions, audit."""
import sqlite3

import pytest

from app import (ALLOWED_TRANSITIONS, INVESTIGATION_STATUSES,
                 InvestigationTransitionError, canonical_investigation_status,
                 get_investigation_status, set_investigation_status)
from database import SCHEMA_VERSION, init_db


@pytest.fixture()
def lifecycle_db(tmp_path):
    dbfile = str(tmp_path / 'lifecycle.sqlite')
    init_db(dbfile)
    with sqlite3.connect(dbfile) as connection:
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details) "
            "VALUES ('2025-01-01T00:00:00Z', 'BRUTE_FORCE', 'HIGH', 'lifecycle row')")
        connection.commit()
    return dbfile


def _alert_id(dbfile):
    with sqlite3.connect(dbfile) as connection:
        return connection.execute('SELECT id FROM alerts LIMIT 1').fetchone()[0]


def _audit_rows(dbfile, alert_id):
    with sqlite3.connect(dbfile) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(
            'SELECT * FROM investigation_events WHERE alert_id = ? ORDER BY id',
            (alert_id,))]


# -- canonical states and aliases ---------------------------------------------

def test_canonical_status_constants():
    assert INVESTIGATION_STATUSES == ('new', 'investigating', 'resolved', 'dismissed')
    assert set(ALLOWED_TRANSITIONS) == set(INVESTIGATION_STATUSES)
    assert SCHEMA_VERSION >= 3


def test_canonical_status_accepts_canonical_and_alias_inputs():
    for status in INVESTIGATION_STATUSES:
        assert canonical_investigation_status(status) == status
    assert canonical_investigation_status('in_progress') == 'investigating'
    assert canonical_investigation_status('closed') == 'resolved'
    # Case and surrounding whitespace are tolerated; values are normalized.
    assert canonical_investigation_status('  IN_PROGRESS ') == 'investigating'
    assert canonical_investigation_status('New') == 'new'


def test_canonical_status_rejects_unknown_values():
    for bad in ('bogus', 'open', 'wip', '', 'new; DROP TABLE alerts'):
        with pytest.raises(ValueError):
            canonical_investigation_status(bad)
    with pytest.raises(ValueError):
        canonical_investigation_status(None)
    with pytest.raises(ValueError):
        canonical_investigation_status(1)


def test_transition_matrix_is_deterministic():
    assert ALLOWED_TRANSITIONS['new'] == frozenset(
        {'new', 'investigating', 'resolved', 'dismissed'})
    assert ALLOWED_TRANSITIONS['investigating'] == frozenset(
        {'investigating', 'resolved', 'dismissed'})
    assert ALLOWED_TRANSITIONS['resolved'] == frozenset(
        {'investigating', 'dismissed'})
    assert ALLOWED_TRANSITIONS['dismissed'] == frozenset({'investigating'})


# -- transitions and audit ------------------------------------------------------

def test_valid_transition_persists_and_audits(lifecycle_db):
    alert_id = _alert_id(lifecycle_db)
    assert get_investigation_status(alert_id, lifecycle_db) == 'new'
    assert set_investigation_status(alert_id, 'investigating', lifecycle_db) is True
    assert get_investigation_status(alert_id, lifecycle_db) == 'investigating'
    rows = _audit_rows(lifecycle_db, alert_id)
    assert len(rows) == 1
    assert rows[0]['from_status'] == 'new'
    assert rows[0]['to_status'] == 'investigating'
    assert rows[0]['source'] == 'api'
    assert rows[0]['changed_at']


def test_alias_inputs_canonicalize_before_storage(lifecycle_db):
    alert_id = _alert_id(lifecycle_db)
    assert set_investigation_status(alert_id, 'in_progress', lifecycle_db) is True
    assert get_investigation_status(alert_id, lifecycle_db) == 'investigating'
    assert set_investigation_status(alert_id, 'closed', lifecycle_db) is True
    assert get_investigation_status(alert_id, lifecycle_db) == 'resolved'
    rows = _audit_rows(lifecycle_db, alert_id)
    assert [(row['from_status'], row['to_status']) for row in rows] == \
        [('new', 'investigating'), ('investigating', 'resolved')]


def test_full_lifecycle_walk_with_audit_trail(lifecycle_db):
    alert_id = _alert_id(lifecycle_db)
    for status in ('investigating', 'resolved', 'investigating', 'dismissed'):
        assert set_investigation_status(
            alert_id, status, lifecycle_db, source='analyst') is True
    assert get_investigation_status(alert_id, lifecycle_db) == 'dismissed'
    rows = _audit_rows(lifecycle_db, alert_id)
    assert [(row['from_status'], row['to_status'], row['source']) for row in rows] == [
        ('new', 'investigating', 'analyst'),
        ('investigating', 'resolved', 'analyst'),
        ('resolved', 'investigating', 'analyst'),
        ('investigating', 'dismissed', 'analyst'),
    ]


def test_invalid_transition_is_rejected_and_state_unchanged(lifecycle_db):
    alert_id = _alert_id(lifecycle_db)
    set_investigation_status(alert_id, 'dismissed', lifecycle_db)
    with pytest.raises(InvestigationTransitionError) as excinfo:
        set_investigation_status(alert_id, 'resolved', lifecycle_db)
    assert 'dismissed -> resolved' in str(excinfo.value)
    assert get_investigation_status(alert_id, lifecycle_db) == 'dismissed'
    # The rejected transition must not leave an audit row behind.
    rows = _audit_rows(lifecycle_db, alert_id)
    assert [(row['from_status'], row['to_status']) for row in rows] == \
        [('new', 'dismissed')]


def test_invalid_transition_from_resolved_to_new(lifecycle_db):
    alert_id = _alert_id(lifecycle_db)
    set_investigation_status(alert_id, 'resolved', lifecycle_db)
    with pytest.raises(InvestigationTransitionError):
        set_investigation_status(alert_id, 'new', lifecycle_db)
    assert get_investigation_status(alert_id, lifecycle_db) == 'resolved'


def test_unknown_status_value_is_rejected(lifecycle_db):
    alert_id = _alert_id(lifecycle_db)
    with pytest.raises(ValueError):
        set_investigation_status(alert_id, 'nonsense', lifecycle_db)
    assert get_investigation_status(alert_id, lifecycle_db) == 'new'
    assert _audit_rows(lifecycle_db, alert_id) == []


def test_unknown_alert_returns_false_without_audit(lifecycle_db):
    assert set_investigation_status(999999, 'investigating', lifecycle_db) is False
    with sqlite3.connect(lifecycle_db) as connection:
        count = connection.execute(
            'SELECT COUNT(*) FROM investigation_events').fetchone()[0]
    assert count == 0


def test_legacy_stored_status_is_tolerated_by_matrix(lifecycle_db):
    """A pre-Phase-3 row with 'in_progress' still transitions sensibly."""
    alert_id = _alert_id(lifecycle_db)
    with sqlite3.connect(lifecycle_db) as connection:
        connection.execute(
            "UPDATE alerts SET investigation_status = 'in_progress' WHERE id = ?",
            (alert_id,))
        connection.commit()
    assert set_investigation_status(alert_id, 'resolved', lifecycle_db) is True
    assert get_investigation_status(alert_id, lifecycle_db) == 'resolved'
    rows = _audit_rows(lifecycle_db, alert_id)
    assert rows[0]['from_status'] == 'in_progress'
    assert rows[0]['to_status'] == 'resolved'


# -- schema migration canonicalization -------------------------------------------

def test_migration_canonicalizes_phase2_status_values(tmp_path):
    dbfile = str(tmp_path / 'migrate.sqlite')
    init_db(dbfile)
    with sqlite3.connect(dbfile) as connection:
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details, investigation_status) "
            "VALUES ('2025-01-01T00:00:00Z', 'BRUTE_FORCE', 'HIGH', 'legacy a', "
            "'in_progress')")
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details, investigation_status) "
            "VALUES ('2025-01-01T00:00:01Z', 'PORT_SCAN', 'MEDIUM', 'legacy b', "
            "'closed')")
        # Pretend this database predates Phase 3.
        connection.execute('PRAGMA user_version = 2')
        connection.commit()
    init_db(dbfile)   # re-run migration
    with sqlite3.connect(dbfile) as connection:
        statuses = dict(connection.execute(
            'SELECT details, investigation_status FROM alerts'))
        version = connection.execute('PRAGMA user_version').fetchone()[0]
    assert statuses == {'legacy a': 'investigating', 'legacy b': 'resolved'}
    assert version == SCHEMA_VERSION


def test_audit_rows_cascade_with_alert_deletion(lifecycle_db):
    alert_id = _alert_id(lifecycle_db)
    set_investigation_status(alert_id, 'investigating', lifecycle_db)
    with sqlite3.connect(lifecycle_db) as connection:
        connection.execute('PRAGMA foreign_keys = ON')
        connection.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
        connection.commit()
        remaining = connection.execute(
            'SELECT COUNT(*) FROM investigation_events').fetchone()[0]
    assert remaining == 0
