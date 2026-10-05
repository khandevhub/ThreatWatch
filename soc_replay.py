"""Sequential attack replay over the existing simulation lab.

Replays a generated scenario's events one at a time through the REAL
pipeline (``detector.process_event``), so detection, correlation, risk,
Jev, and alerts behave exactly as in batch processing. No alert is ever
created directly by this module and no network traffic is generated.

The replay state (``soc_replays`` + ``soc_replay_events``) is a lab
artifact only: it drives the visible step-by-step UI, can be restarted,
and is fully removed by the simulation reset.
"""

from __future__ import annotations

import json

from database import connect, utc_now
from detector import process_event
from soc_simulation import (SimulationError, _connect, _alerts_created_for,
                            get_run)

__all__ = [
    'ReplayError', 'ensure_replay_schema', 'start_replay', 'get_replay',
    'replay_step', 'replay_full',
]

# Client-observed pacing hint; the server never sleeps on request threads.
MIN_STEP_DELAY_MS = 0
MAX_STEP_DELAY_MS = 5000


class ReplayError(Exception):
    """Raised for invalid replay requests."""


def ensure_replay_schema(db_file=None):
    """Create the replay bookkeeping tables (idempotent, lab-scope only)."""
    with connect(db_file) as connection:
        connection.execute('''
            CREATE TABLE IF NOT EXISTS soc_replays (
                replay_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                scenario_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN (
                    'running', 'complete')),
                total_events INTEGER NOT NULL CHECK (total_events >= 0),
                processed_events INTEGER NOT NULL CHECK (processed_events >= 0),
                step_delay_ms INTEGER NOT NULL DEFAULT 300,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        connection.execute('''
            CREATE TABLE IF NOT EXISTS soc_replay_events (
                replay_id TEXT NOT NULL REFERENCES soc_replays(replay_id)
                    ON DELETE CASCADE,
                event_index INTEGER NOT NULL CHECK (event_index >= 0),
                event_id TEXT NOT NULL,
                accepted INTEGER NOT NULL CHECK (accepted IN (0, 1)),
                alert_ids_json TEXT NOT NULL DEFAULT '[]',
                processed_at TEXT,
                PRIMARY KEY (replay_id, event_index)
            )
        ''')


def _replay_row(db_file, replay_id):
    with connect(db_file) as connection:
        return connection.execute(
            'SELECT replay_id, run_id, scenario_id, status, total_events, '
            'processed_events, step_delay_ms, created_at, updated_at '
            'FROM soc_replays WHERE replay_id = ?', (replay_id,)).fetchone()


def _replay_view(db_file, row, include_events=False):
    view = dict(row)
    view['processed_events'] = int(view['processed_events'])
    view['total_events'] = int(view['total_events'])
    if include_events:
        with connect(db_file) as connection:
            rows = connection.execute(
                'SELECT event_index, event_id, accepted, alert_ids_json, '
                'processed_at FROM soc_replay_events WHERE replay_id = ? '
                'ORDER BY event_index', (view['replay_id'],)).fetchall()
        events = []
        for event_row in rows:
            event = dict(event_row)
            try:
                event['alert_ids'] = json.loads(event.pop('alert_ids_json'))
            except (TypeError, ValueError):
                event['alert_ids'] = []
            event['accepted'] = bool(event['accepted'])
            events.append(event)
        view['events'] = events
    return view


def start_replay(run_id, step_delay_ms=300, db_file=None):
    """Start (or restart) a sequential replay for one generated run.

    Restarting the same run creates a fresh replay bookkeeping row; the
    underlying events are unchanged and detection stays idempotent
    (identical event ids are rejected by the pipeline, not duplicated).
    """
    if not isinstance(run_id, str) or not run_id.strip():
        raise ReplayError('run_id is required')
    run_id = run_id.strip()[:64]
    try:
        delay = int(step_delay_ms)
    except (TypeError, ValueError):
        raise ReplayError('step_delay_ms must be an integer') from None
    if not MIN_STEP_DELAY_MS <= delay <= MAX_STEP_DELAY_MS:
        raise ReplayError(
            f'step_delay_ms must be between {MIN_STEP_DELAY_MS} and '
            f'{MAX_STEP_DELAY_MS}')
    try:
        run = get_run(run_id, db_file=db_file)
    except SimulationError as exc:
        raise ReplayError(f'run not found: {run_id}') from exc
    if run.get('status') != 'generated':
        raise ReplayError(
            'run has already been processed; generate the scenario again '
            'for a fresh replay')
    event_ids = list(run.get('event_ids') or [])
    ensure_replay_schema(db_file)
    from uuid import uuid4
    replay_id = f'RPL-{uuid4().hex[:12]}'
    now = utc_now()
    with _connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            connection.execute(
                'INSERT INTO soc_replays (replay_id, run_id, scenario_id, '
                'status, total_events, processed_events, step_delay_ms, '
                'created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
                (replay_id, run_id, run['scenario_id'], 'running',
                 len(event_ids), 0, delay, now, now))
            connection.executemany(
                'INSERT INTO soc_replay_events (replay_id, event_index, '
                'event_id, accepted, alert_ids_json) VALUES (?,?,?,?,?)',
                [(replay_id, index, event_id, 0, '[]')
                 for index, event_id in enumerate(event_ids)])
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return _replay_view(db_file, _replay_row(db_file, replay_id),
                        include_events=True)


def get_replay(replay_id, db_file=None, include_events=True):
    ensure_replay_schema(db_file)
    row = _replay_row(db_file, replay_id)
    if row is None:
        return None
    return _replay_view(db_file, row, include_events=include_events)


def replay_step(replay_id, db_file=None):
    """Process the next event of a running replay through the real pipeline.

    Each call feeds exactly one stored payload to
    ``detector.process_event`` — the same ingestion + detection path used
    everywhere in ThreatWatch. Returns the replay view plus the step
    result (accepted flag, alert ids created by this event).
    """
    ensure_replay_schema(db_file)
    row = _replay_row(db_file, replay_id)
    if row is None:
        raise ReplayError(f'replay not found: {replay_id}')
    if row['status'] != 'running':
        raise ReplayError('replay is already complete')
    with _connect(db_file) as connection:
        next_row = connection.execute(
            'SELECT event_index, event_id FROM soc_replay_events '
            'WHERE replay_id = ? AND processed_at IS NULL '
            'ORDER BY event_index LIMIT 1', (replay_id,)).fetchone()
    if next_row is None:
        return _finish_replay(db_file, replay_id), None
    with _connect(db_file) as connection:
        payload_row = connection.execute(
            'SELECT payload_json FROM simulation_events WHERE run_id = ? '
            'AND event_index = ?',
            (row['run_id'], next_row['event_index'])).fetchone()
    if payload_row is None:
        raise ReplayError('stored payload missing for replay event')
    payload = json.loads(payload_row['payload_json'])
    accepted = bool(process_event(payload, db_file=db_file))
    alert_ids = []
    if accepted:
        alert_ids = _alerts_created_for(db_file, payload['event_id'])
    with _connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            connection.execute(
                'UPDATE soc_replay_events SET accepted = ?, '
                'alert_ids_json = ?, processed_at = ? '
                'WHERE replay_id = ? AND event_index = ?',
                (1 if accepted else 0, json.dumps(alert_ids), utc_now(),
                 replay_id, next_row['event_index']))
            connection.execute(
                'UPDATE soc_replays SET processed_events = processed_events + 1, '
                'updated_at = ? WHERE replay_id = ?',
                (utc_now(), replay_id))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    step = {
        'event_index': next_row['event_index'],
        'event_id': payload['event_id'],
        'accepted': accepted,
        'alert_ids': alert_ids,
        'remaining': int(row['total_events']) - int(row['processed_events']) - 1,
    }
    return get_replay(replay_id, db_file=db_file), step


def replay_full(replay_id, max_events=200, db_file=None):
    """Process the whole remaining replay in order (bounded).

    Used by the demo/validation paths and tests; the dashboard UI uses
    ``replay_step`` so events appear one at a time in the live stream.
    """
    limit = max(1, min(int(max_events), 500))
    steps = []
    for _ in range(limit):
        view, step = replay_step(replay_id, db_file=db_file)
        if step is None:
            break
        steps.append(step)
    return view, steps


def _finish_replay(db_file, replay_id):
    with _connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            connection.execute(
                'UPDATE soc_replays SET status = ?, updated_at = ? '
                'WHERE replay_id = ?', ('complete', utc_now(), replay_id))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return get_replay(replay_id, db_file=db_file)
