"""Analyst case layer over the existing SOAR incident records.

Adds a purpose-built overlay (``soc_cases`` + ``soc_case_notes``) so the
analyst workflow (new -> investigating -> confirmed_threat / false_positive
-> closed, plus analyst notes) can evolve without migrating the shipped
``soar_incidents`` CHECK constraint. Incidents themselves stay untouched:
a case is always created for (or reuses) the incident the existing
``IncidentService`` already produced.

Every state transition and note appends a row to the existing
``soar_audit`` trail (audit columns are nullable; case rows carry
``execution_id = NULL`` and a ``case_*`` event type), so the analyst
workflow is visible in the same audit timeline as the SOAR engine.

All values are bounded and parameterized; there is no SQL built from
user input. This module never executes actions, calls the network, or
bypasses detection: it only records analyst decisions about stored data.
"""

from __future__ import annotations

import hashlib
import json

from database import connect, utc_now
from soar import USER_ACTOR_RE

__all__ = [
    'CaseError', 'ensure_case_schema', 'open_case', 'get_case',
    'list_cases', 'case_for_alert', 'transition_case', 'add_case_note',
    'CASE_STATES', 'CASE_TRANSITIONS', 'NOTE_MAX_CHARS',
]


class CaseError(Exception):
    """Raised for invalid case requests (unknown state, bad actor, ...)."""


CASE_STATES = ('new', 'investigating', 'confirmed_threat', 'false_positive',
               'closed')

# Explicit transition table; anything not listed is rejected.
CASE_TRANSITIONS = {
    'new': frozenset({'investigating', 'confirmed_threat', 'false_positive',
                      'closed'}),
    'investigating': frozenset({'confirmed_threat', 'false_positive',
                                'closed'}),
    'confirmed_threat': frozenset({'closed', 'investigating'}),
    'false_positive': frozenset({'closed', 'investigating'}),
    'closed': frozenset(),
}

DECISION_STATES = frozenset({'confirmed_threat', 'false_positive'})
NOTE_MAX_CHARS = 2000


def ensure_case_schema(db_file=None):
    """Create the case overlay tables (idempotent, additive only)."""
    with connect(db_file) as connection:
        connection.execute('''
            CREATE TABLE IF NOT EXISTS soc_cases (
                case_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                alert_id INTEGER,
                status TEXT NOT NULL CHECK (status IN (
                    'new', 'investigating', 'confirmed_threat',
                    'false_positive', 'closed')),
                decision TEXT,
                analyst TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (incident_id)
            )
        ''')
        connection.execute('''
            CREATE TABLE IF NOT EXISTS soc_case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL REFERENCES soc_cases(case_id)
                    ON DELETE CASCADE,
                author TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        connection.execute(
            'CREATE INDEX IF NOT EXISTS idx_soc_cases_alert '
            'ON soc_cases(alert_id)')
        connection.execute(
            'CREATE INDEX IF NOT EXISTS idx_soc_case_notes_case '
            'ON soc_case_notes(case_id)')


def _case_row(db_file, case_id):
    with connect(db_file) as connection:
        return connection.execute(
            'SELECT case_id, incident_id, alert_id, status, decision, '
            'analyst, created_at, updated_at FROM soc_cases '
            'WHERE case_id = ?', (case_id,)).fetchone()


def _audit_case(connection, *, alert_id, actor, event_type, from_state,
                to_state, result=None):
    """Append one case event to the shared soar_audit trail."""
    connection.execute(
        'INSERT INTO soar_audit (execution_id, playbook_id, action_index, '
        'alert_id, actor, event_type, from_state, to_state, dry_run, '
        'approval_state, result_json, failure_reason, created_at) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (None, None, None, alert_id, str(actor)[:80], str(event_type)[:40],
         from_state, to_state, 0, None,
         json.dumps(result)[:4000] if result is not None else None,
         None, utc_now()))


def _load_case_with_notes(db_file, case_id):
    row = _case_row(db_file, case_id)
    if row is None:
        return None
    case = dict(row)
    with connect(db_file) as connection:
        case['notes'] = [dict(note) for note in connection.execute(
            'SELECT id, author, body, created_at FROM soc_case_notes '
            'WHERE case_id = ? ORDER BY id', (case_id,))]
    return case


def open_case(incident_id, alert_id=None, analyst='analyst', db_file=None):
    """Open (or return the existing) case for one incident.

    Idempotent per incident: reopening returns the current case unchanged
    so repeated clicks never duplicate workflow state.
    """
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise CaseError('incident_id is required')
    if not isinstance(analyst, str) or not USER_ACTOR_RE.match(analyst):
        raise CaseError('analyst must be a bounded logical username')
    incident_id = incident_id.strip()[:64]
    ensure_case_schema(db_file)
    with connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            row = connection.execute(
                'SELECT case_id FROM soc_cases WHERE incident_id = ?',
                (incident_id,)).fetchone()
            if row:
                connection.commit()
                existing = row['case_id']
            else:
                now = utc_now()
                digest = hashlib.sha256(
                    json.dumps([incident_id, now], default=str)
                    .encode('utf-8')).hexdigest().upper()
                case_id = f'CASE-{digest[:12]}'
                connection.execute(
                    'INSERT INTO soc_cases (case_id, incident_id, alert_id, '
                    'status, decision, analyst, created_at, updated_at) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (case_id, incident_id,
                     alert_id if isinstance(alert_id, int)
                     and not isinstance(alert_id, bool) else None,
                     'new', None, analyst, now, now))
                _audit_case(connection, alert_id=alert_id, actor=analyst,
                            event_type='case_opened', from_state=None,
                            to_state='new',
                            result={'case_id': case_id,
                                    'incident_id': incident_id})
                connection.commit()
                existing = case_id
        except Exception:
            connection.rollback()
            raise
    return _load_case_with_notes(db_file, existing)


def get_case(case_id, db_file=None):
    ensure_case_schema(db_file)
    return _load_case_with_notes(db_file, case_id)


def list_cases(limit=50, db_file=None):
    limit = max(1, min(int(limit), 200))
    ensure_case_schema(db_file)
    with connect(db_file) as connection:
        rows = connection.execute(
            'SELECT case_id, incident_id, alert_id, status, decision, '
            'analyst, created_at, updated_at FROM soc_cases '
            'ORDER BY updated_at DESC, case_id LIMIT ?', (limit,)).fetchall()
    return [dict(row) for row in rows]


def case_for_alert(alert_id, db_file=None):
    """Return the newest case linked to this alert, if any."""
    ensure_case_schema(db_file)
    if not isinstance(alert_id, int) or isinstance(alert_id, bool):
        raise CaseError('alert_id must be an integer')
    with connect(db_file) as connection:
        rows = connection.execute(
            'SELECT c.case_id, i.alert_ids_json FROM soc_cases c '
            'JOIN soar_incidents i ON i.incident_id = c.incident_id '
            'ORDER BY c.updated_at DESC').fetchall()
    for row in rows:
        try:
            linked = json.loads(row['alert_ids_json'] or '[]')
        except (TypeError, ValueError):
            linked = []
        if alert_id in linked:
            return _load_case_with_notes(db_file, row['case_id'])
    return None


def transition_case(case_id, to_state, analyst='analyst', note=None,
                    db_file=None):
    """Move a case along the analyst workflow; validates the transition.

    ``confirmed_threat`` and ``false_positive`` require a decision note so
    the audit trail records *why* the analyst decided, not just what.
    """
    if not isinstance(analyst, str) or not USER_ACTOR_RE.match(analyst):
        raise CaseError('analyst must be a bounded logical username')
    if to_state not in CASE_STATES:
        raise CaseError(f'unknown case state: {to_state}')
    body = None
    if note is not None:
        if not isinstance(note, str) or not note.strip():
            raise CaseError('note must be a non-empty string')
        body = note.strip()[:NOTE_MAX_CHARS]
    if to_state in DECISION_STATES and not body:
        raise CaseError(
            f'a decision note is required to mark a case {to_state}')
    ensure_case_schema(db_file)
    with connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            row = connection.execute(
                'SELECT status, alert_id, incident_id, decision FROM '
                'soc_cases WHERE case_id = ?', (case_id,)).fetchone()
            if row is None:
                raise CaseError(f'case not found: {case_id}')
            current = row['status']
            if to_state not in CASE_TRANSITIONS[current]:
                raise CaseError(
                    f'invalid transition: {current} -> {to_state}')
            now = utc_now()
            decision = (to_state if to_state in DECISION_STATES
                        else row['decision'])
            connection.execute(
                'UPDATE soc_cases SET status = ?, decision = ?, '
                'updated_at = ? WHERE case_id = ?',
                (to_state, decision, now, case_id))
            _audit_case(
                connection, alert_id=row['alert_id'], actor=analyst,
                event_type='case_state_transition',
                from_state=current, to_state=to_state,
                result={'case_id': case_id, 'decision': decision,
                        'incident_id': row['incident_id']})
            if body:
                connection.execute(
                    'INSERT INTO soc_case_notes (case_id, author, body, '
                    'created_at) VALUES (?,?,?,?)',
                    (case_id, analyst, body, now))
                _audit_case(
                    connection, alert_id=row['alert_id'], actor=analyst,
                    event_type='case_note_added', from_state=None,
                    to_state=None,
                    result={'case_id': case_id, 'note_chars': len(body)})
            connection.commit()
        except CaseError:
            connection.rollback()
            raise
        except Exception:
            connection.rollback()
            raise
    return _load_case_with_notes(db_file, case_id)


def add_case_note(case_id, author='analyst', body='', db_file=None):
    """Append an analyst note; every note is an audit event."""
    if not isinstance(author, str) or not USER_ACTOR_RE.match(author):
        raise CaseError('author must be a bounded logical username')
    if not isinstance(body, str) or not body.strip():
        raise CaseError('note body must be a non-empty string')
    body = body.strip()[:NOTE_MAX_CHARS]
    ensure_case_schema(db_file)
    with connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            row = connection.execute(
                'SELECT alert_id FROM soc_cases WHERE case_id = ?',
                (case_id,)).fetchone()
            if row is None:
                raise CaseError(f'case not found: {case_id}')
            connection.execute(
                'INSERT INTO soc_case_notes (case_id, author, body, '
                'created_at) VALUES (?,?,?,?)',
                (case_id, author, body, utc_now()))
            _audit_case(connection, alert_id=row['alert_id'], actor=author,
                        event_type='case_note_added', from_state=None,
                        to_state=None,
                        result={'case_id': case_id, 'note_chars': len(body)})
            connection.execute(
                'UPDATE soc_cases SET updated_at = ? WHERE case_id = ?',
                (utc_now(), case_id))
            connection.commit()
        except CaseError:
            connection.rollback()
            raise
        except Exception:
            connection.rollback()
            raise
    return _load_case_with_notes(db_file, case_id)
