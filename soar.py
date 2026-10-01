"""SOAR execution engine (Phase 5E/5F/5G/5H/5I/5K/5M/5O/5P).

The engine is the deterministic control plane for playbook executions. It
owns the execution state machine, idempotency keys, approval gates, retries,
cancellation/timeout handling, immutable evidence preservation, incident
dedupe, and the SOAR audit log. AI (Phase 4) may only *suggest* a playbook
by ID; the engine re-validates the suggestion against triggers, policy, and
approvals — AI output never executes anything by itself.

SQLite persistence lives in the schema-v4 ``soar_*`` tables (see
``database.init_db``); all writes are parameterized, transactional, and
audited. Raw errors are never persisted: failures are mapped to bounded
error categories with redacted messages.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3

from actions import ActionError, default_action_providers
from database import connect, utc_now
from evidence import redact_text
from playbook import (PlaybookValidationError, PolicyEngine,
                      built_in_playbooks, definition_hash,
                      playbook_matches, validate_playbook_definition)

DB_FILE = os.environ.get('DB_FILE', 'db.sqlite')

# ---------------------------------------------------------------------------
# States and transitions (5F)
# ---------------------------------------------------------------------------

EXECUTION_STATES = (
    'PENDING', 'VALIDATING', 'WAITING_APPROVAL', 'APPROVED', 'RUNNING',
    'SUCCEEDED', 'VALIDATION_FAILED', 'APPROVAL_REJECTED',
    'APPROVAL_EXPIRED', 'ACTION_FAILED', 'CANCELLED', 'TIMED_OUT')

TERMINAL_STATES = ('SUCCEEDED', 'VALIDATION_FAILED', 'APPROVAL_REJECTED',
                   'APPROVAL_EXPIRED', 'ACTION_FAILED', 'CANCELLED',
                   'TIMED_OUT')

#: Allowed execution-level transitions. Missing key => transition forbidden.
EXECUTION_TRANSITIONS = {
    'PENDING': {'PENDING', 'VALIDATING', 'CANCELLED'},
    'VALIDATING': {'VALIDATING', 'WAITING_APPROVAL', 'APPROVED',
                   'VALIDATION_FAILED', 'CANCELLED'},
    'WAITING_APPROVAL': {'WAITING_APPROVAL', 'APPROVED',
                         'APPROVAL_REJECTED', 'APPROVAL_EXPIRED',
                         'CANCELLED'},
    'APPROVED': {'APPROVED', 'RUNNING', 'CANCELLED'},
    'RUNNING': {'RUNNING', 'SUCCEEDED', 'ACTION_FAILED', 'CANCELLED',
                'TIMED_OUT'},
    'SUCCEEDED': set(),
    'VALIDATION_FAILED': set(),
    'APPROVAL_REJECTED': set(),
    'APPROVAL_EXPIRED': set(),
    'ACTION_FAILED': set(),
    'CANCELLED': set(),
    'TIMED_OUT': set(),
}

AGENT = 'system'
USER_ACTOR_RE = re.compile(r'^[\w.\-:@/]{1,80}$')

INCIDENT_STATUSES = ('open', 'contained', 'resolved', 'closed')

MAX_LIST_LIMIT = 100
MAX_TTL_MINUTES = 7 * 24 * 60
DEFAULT_APPROVAL_TTL_MINUTES = 60
MAX_TRIGGER_PAYLOAD_CHARS = 10000
_MAX_CONTEXT_JSON_CHARS = 20000


class SOARError(ValueError):
    """Base class for controlled SOAR failures (API maps to 400/404/409)."""


class PlaybookNotFoundError(SOARError):
    def __init__(self, playbook_id):
        super().__init__(f'playbook not found: {playbook_id}')
        self.playbook_id = playbook_id


class ExecutionNotFoundError(SOARError):
    def __init__(self, execution_id):
        super().__init__(f'SOAR execution not found: {execution_id}')
        self.execution_id = execution_id


class ApprovalNotFoundError(SOARError):
    def __init__(self, approval_id):
        super().__init__(f'SOAR approval not found: {approval_id}')
        self.approval_id = approval_id


class InvalidStateTransition(SOARError):
    def __init__(self, from_state, to_state):
        super().__init__(
            f'invalid SOAR state transition: {from_state} -> {to_state}')
        self.from_state = from_state
        self.to_state = to_state


class ApprovalExpiredError(SOARError):
    pass


class DuplicateExecution(SOARError):
    """An execution already exists for the same idempotency context."""

    def __init__(self, existing):
        super().__init__(
            f"execution already exists: {existing['execution_id']}")
        self.existing_execution_id = existing['execution_id']
        self.existing = existing


# ---------------------------------------------------------------------------
# Audit helper (5H)
# ---------------------------------------------------------------------------

def _audit(con, *, execution_id=None, playbook_id=None, action_index=None,
           alert_id=None, actor=AGENT, event_type, from_state=None,
           to_state=None, dry_run=False, approval_state=None,
           result_json=None, failure_reason=None):
    """Append one SOAR audit row; every value is a bound SQL parameter."""
    con.execute(
        'INSERT INTO soar_audit (execution_id, playbook_id, action_index, '
        'alert_id, actor, event_type, from_state, to_state, dry_run, '
        'approval_state, result_json, failure_reason, created_at) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (execution_id, playbook_id, action_index, alert_id,
         str(actor)[:80], str(event_type)[:40], from_state, to_state,
         1 if dry_run else 0, approval_state,
         json.dumps(result_json)[:4000] if result_json is not None else None,
         redact_text(str(failure_reason))[:300] if failure_reason else None,
         utc_now()))


def _short_hash(prefix, parts):
    digest = hashlib.sha256(
        json.dumps(parts, sort_keys=True, default=str).encode('utf-8')
    ).hexdigest()[:12].upper()
    return f'{prefix}-{digest}'


_SECRET_KEY_HINTS = ('key', 'token', 'secret', 'password', 'credential',
                     'authorization', 'api')


def _redact_secret_keys(payload):
    """Return a copy of a JSON-ish payload with secret-named keys masked.

    ``redact_text`` handles `key=value` and header patterns in free text;
    this complements it for structured payloads where the sensitive value
    sits in a JSON field (e.g. ``{"api_key": "..."}``).
    """
    if isinstance(payload, dict):
        cleaned = {}
        for key, value in payload.items():
            key_text = str(key).lower()
            if any(hint in key_text for hint in _SECRET_KEY_HINTS):
                cleaned[key] = '[REDACTED]'
            else:
                cleaned[key] = _redact_secret_keys(value)
        return cleaned
    if isinstance(payload, list):
        return [_redact_secret_keys(item) for item in payload]
    return payload


# ---------------------------------------------------------------------------
# Evidence preservation (5I)
# ---------------------------------------------------------------------------

def build_execution_evidence(package, execution_id, dry_run,
                             ai_investigation=None):
    """Build the immutable evidence snapshot from an investigation package.

    The snapshot is written once, stored on the execution row, and never
    modified by action execution — actions may read it, never rewrite it.
    All free text passes through secret redaction and is length-bounded.
    """
    alert = package.get('alert') or {}
    evidence = {
        'evidence_id': _short_hash('EV', ['evidence', execution_id]),
        'captured_at': utc_now(),
        'dry_run': bool(dry_run),
        'alert': json.loads(redact_text(json.dumps(alert, default=str))) if alert else {},
        'alert_id': alert.get('id'),
        'risk': package.get('risk'),
        'jev_decision': {
            'priority': alert.get('jev_priority'),
            'attack_category': alert.get('jev_attack_category'),
            'status': alert.get('jev_status'),
            'malicious_likelihood': alert.get('jev_malicious_likelihood'),
            'false_positive_likelihood': alert.get('jev_false_positive_likelihood'),
            'investigation_required': alert.get('jev_investigation_required'),
        },
        'evidence_entities': (package.get('evidence') or {}).get('entities'),
        'timeline': _timeline_head(package.get('timeline')),
        'threat_intel': _bounded_section(package.get('threat_intel')),
        'mitre': _bounded_section(package.get('mitre')),
        'related_alerts': _bounded_section(package.get('related_alerts')),
        'ai_investigation': ai_investigation,
        'playbook_execution_id': execution_id,
    }
    serialized = json.dumps(evidence, default=str)
    if len(serialized) > _MAX_CONTEXT_JSON_CHARS:
        # Bounded evidence: drop the heaviest optional sections first.
        evidence['timeline'] = _timeline_head(evidence.get('timeline'), 20)
        evidence['related_alerts'] = _bounded_section(
            evidence.get('related_alerts'), 5)
        evidence['threat_intel'] = _bounded_section(
            evidence.get('threat_intel'), 5)
    return evidence


def _bounded_section(section, cap=20):
    """Bound a package section (dict with a list payload) without reshaping it."""
    if isinstance(section, dict):
        bounded = dict(section)
        for key, value in section.items():
            if isinstance(value, list):
                bounded[key] = value[:cap]
        return bounded
    if isinstance(section, list):
        return section[:cap]
    return section


def _timeline_head(timeline, cap=50):
    """Bounded head of a Phase 3 timeline dict (it carries entries/truncated)."""
    if not isinstance(timeline, dict):
        return None
    entries = timeline.get('entries') or []
    return {
        'total_events': timeline.get('total_events'),
        'truncated': timeline.get('truncated'),
        'entries': entries[:cap],
    }


# ---------------------------------------------------------------------------
# Incident service (5K)
# ---------------------------------------------------------------------------

class IncidentService:
    """Deterministic incident creation with duplicate prevention."""

    def __init__(self, db_file=None):
        self.db_file = db_file or DB_FILE

    def create_incident(self, title, severity='medium', alert_id=None,
                        correlation_id=None, execution_id=None):
        """Create or reuse an incident; returns ``incident_id`` + ``created``.

        Dedupe key: (title, correlation_id). The same alert re-processed
        reuses the existing incident instead of creating a duplicate.
        """
        title = redact_text(str(title or ''))[:200].strip()
        if not title:
            raise SOARError('incident title must not be empty')
        if severity not in ('low', 'medium', 'high', 'critical'):
            raise SOARError('incident severity must be low|medium|high|critical')
        alert_ids = []
        if alert_id is not None:
            if not isinstance(alert_id, int) or isinstance(alert_id, bool):
                raise SOARError('alert_id must be an integer')
            alert_ids = [int(alert_id)]
        if correlation_id is not None:
            correlation_id = str(correlation_id)[:120]
        now = utc_now()
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                row = con.execute(
                    'SELECT incident_id, alert_ids_json FROM soar_incidents '
                    'WHERE title = ? AND correlation_id IS ?',
                    (title, correlation_id)).fetchone()
                if row:
                    incident_id = row['incident_id']
                    created = False
                    if alert_ids:
                        merged = sorted(set(json.loads(row['alert_ids_json']))
                                        | set(alert_ids))
                        if merged != json.loads(row['alert_ids_json']):
                            con.execute(
                                'UPDATE soar_incidents SET alert_ids_json = ?, '
                                'updated_at = ? WHERE incident_id = ?',
                                (json.dumps(merged), now, incident_id))
                else:
                    incident_id = _short_hash('INC', ['incident', title,
                                                      correlation_id, now[:19]])
                    con.execute(
                        'INSERT INTO soar_incidents (incident_id, title, '
                        'severity, status, alert_ids_json, correlation_id, '
                        'created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)',
                        (incident_id, title, severity, 'open',
                         json.dumps(alert_ids), correlation_id, now, now))
                    created = True
                if execution_id:
                    _audit(con, execution_id=execution_id, alert_id=alert_id,
                           event_type='incident_created' if created
                           else 'incident_reused',
                           to_state='open' if created else None, dry_run=False,
                           result_json={'incident_id': incident_id,
                                        'created': created})
                con.commit()
                return {'incident_id': incident_id, 'created': created}
            except Exception:
                con.rollback()
                raise

    def list_incidents(self, limit=50):
        limit = max(1, min(int(limit), MAX_LIST_LIMIT))
        with connect(self.db_file) as con:
            rows = con.execute(
                'SELECT incident_id, title, severity, status, alert_ids_json, '
                'correlation_id, created_at, updated_at FROM soar_incidents '
                'ORDER BY created_at DESC, incident_id LIMIT ?',
                (limit,)).fetchall()
        return [self._view(row) for row in rows]

    def get_incident(self, incident_id):
        with connect(self.db_file) as con:
            row = con.execute(
                'SELECT incident_id, title, severity, status, alert_ids_json, '
                'correlation_id, created_at, updated_at FROM soar_incidents '
                'WHERE incident_id = ?', (incident_id,)).fetchone()
        return self._view(row) if row else None

    @staticmethod
    def _view(row):
        return dict(row) | {'alert_ids': json.loads(row['alert_ids_json'])}


# ---------------------------------------------------------------------------
# SOAR engine
# ---------------------------------------------------------------------------

class SOAREngine:
    """Deterministic playbook execution engine with audit and approvals."""

    def __init__(self, db_file=None, action_providers=None,
                 policy_engine=None, incident_service=None):
        self.db_file = db_file or DB_FILE
        self.action_providers = action_providers or default_action_providers()
        self.policy_engine = policy_engine or PolicyEngine()
        self.incident_service = incident_service or IncidentService(self.db_file)

    # -- playbook registry ------------------------------------------------

    def register_built_ins(self):
        """Insert shipped playbooks that are not yet present. Idempotent."""
        registered = []
        for definition in built_in_playbooks():
            normalized = validate_playbook_definition(definition)
            with connect(self.db_file) as con:
                row = con.execute(
                    'SELECT playbook_id FROM soar_playbooks WHERE playbook_id = ?',
                    (normalized['playbook_id'],)).fetchone()
            if row is None:
                self.save_playbook(definition)
                registered.append(normalized['playbook_id'])
        return registered

    def save_playbook(self, definition):
        """Validate and upsert one playbook definition (versioned)."""
        normalized = validate_playbook_definition(definition)
        # Policy must accept the definition at validation time (fail closed).
        plan = self.policy_engine.evaluate(normalized)
        if not plan['allowed']:
            raise PlaybookValidationError(f"policy rejects playbook: {plan['reason']}")
        now = utc_now()
        payload = json.dumps(normalized, sort_keys=True)
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                con.execute(
                    'INSERT INTO soar_playbooks (playbook_id, name, description, '
                    'version, enabled, definition_json, definition_sha256, '
                    'created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) '
                    'ON CONFLICT(playbook_id) DO UPDATE SET '
                    'name = excluded.name, description = excluded.description, '
                    'version = excluded.version, enabled = excluded.enabled, '
                    'definition_json = excluded.definition_json, '
                    'definition_sha256 = excluded.definition_sha256, '
                    'updated_at = excluded.updated_at',
                    (normalized['playbook_id'], normalized['name'],
                     normalized['description'], normalized['version'],
                     1 if normalized['enabled'] else 0, payload,
                     definition_hash(normalized), now, now))
                _audit(con, playbook_id=normalized['playbook_id'],
                       event_type='playbook_saved',
                       to_state=f"v{normalized['version']}", dry_run=False,
                       result_json={'enabled': normalized['enabled'],
                                    'version': normalized['version']})
                con.commit()
            except Exception:
                con.rollback()
                raise
        return normalized

    def get_playbook(self, playbook_id):
        with connect(self.db_file) as con:
            row = con.execute(
                'SELECT playbook_id, name, description, version, enabled, '
                'definition_json, definition_sha256, created_at, updated_at '
                'FROM soar_playbooks WHERE playbook_id = ?',
                (playbook_id,)).fetchone()
        return self._playbook_view(row) if row else None

    def list_playbooks(self):
        with connect(self.db_file) as con:
            rows = con.execute(
                'SELECT playbook_id, name, description, version, enabled, '
                'definition_json, definition_sha256, created_at, updated_at '
                'FROM soar_playbooks ORDER BY playbook_id').fetchall()
        return [self._playbook_view(row) for row in rows]

    def set_playbook_enabled(self, playbook_id, enabled, actor=AGENT):
        if not isinstance(enabled, bool):
            raise SOARError('enabled must be a boolean')
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                cursor = con.execute(
                    'UPDATE soar_playbooks SET enabled = ?, updated_at = ? '
                    'WHERE playbook_id = ?',
                    (1 if enabled else 0, utc_now(), playbook_id))
                if cursor.rowcount == 0:
                    raise PlaybookNotFoundError(playbook_id)
                _audit(con, playbook_id=playbook_id, actor=actor,
                       event_type='playbook_enabled' if enabled
                       else 'playbook_disabled', dry_run=False,
                       result_json={'enabled': enabled})
                con.commit()
            except Exception:
                con.rollback()
                raise

    @staticmethod
    def _playbook_view(row):
        view = dict(row)
        view['definition'] = json.loads(view.pop('definition_json'))
        view['enabled'] = bool(view['enabled'])
        return view

    # -- execution lifecycle (5E/5F/5O/5P) ---------------------------------

    def start_execution(self, playbook_id, alert, *, dry_run=True,
                        actor=AGENT, trigger_payload=None,
                        ai_recommendation=None):
        """Start (or dedupe) a playbook execution for an alert.

        Steps: playbook lookup -> enabled check -> trigger evaluation ->
        policy evaluation -> idempotency dedupe -> evidence snapshot ->
        persist PENDING. Returns the execution view. Raises
        :class:`DuplicateExecution` when an identical execution exists.
        """
        playbook = self.get_playbook(playbook_id)
        if playbook is None:
            raise PlaybookNotFoundError(playbook_id)
        if not playbook['enabled']:
            raise SOARError(f"playbook is disabled: {playbook_id}")
        definition = playbook['definition']
        alert = dict(alert) if alert else {}
        if not playbook_matches(definition, alert):
            raise SOARError('alert does not match playbook triggers')
        plan = self.policy_engine.evaluate(definition)
        if not plan['allowed']:
            raise SOARError(f"policy rejects playbook: {plan['reason']}")
        if plan['force_dry_run']:
            dry_run = True

        alert_id = alert.get('id')
        correlation_id = alert.get('correlation_id')
        idempotency_key = self.idempotency_key(
            playbook_id, playbook['version'], alert_id, correlation_id)
        existing = self.get_execution_by_idempotency_key(idempotency_key)
        if existing is not None:
            raise DuplicateExecution(existing)

        execution_id = _short_hash('EXE', ['execution', playbook_id,
                                           alert_id, idempotency_key,
                                           utc_now()])
        package = self._load_investigation_package(alert_id)
        evidence = build_execution_evidence(
            package, execution_id, dry_run,
            ai_investigation=self._load_ai_result(alert_id))
        trigger = {
            'playbook_id': playbook_id,
            'playbook_version': playbook['version'],
            'matched_triggers': [t for t in definition['triggers']
                                 if playbook_matches({'triggers': [t]}, alert)],
            'payload': {},
        }
        if trigger_payload is not None:
            if not isinstance(trigger_payload, dict):
                raise SOARError('trigger_payload must be an object')
            trigger['payload'] = json.loads(redact_text(
                json.dumps(trigger_payload, default=str))) \
                if len(json.dumps(trigger_payload)) <= MAX_TRIGGER_PAYLOAD_CHARS \
                else {'truncated': True}
        context = {
            'execution_id': execution_id,
            'playbook_id': playbook_id,
            'alert_id': alert_id,
            'correlation_id': correlation_id,
            'dry_run': bool(dry_run),
            'actor': actor,
            'ai_recommendation': ai_recommendation,
        }
        now = utc_now()
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                con.execute(
                    'INSERT INTO soar_executions (execution_id, playbook_id, '
                    'playbook_version, alert_id, state, dry_run, '
                    'idempotency_key, trigger_json, context_json, '
                    'evidence_json, error, created_at, updated_at) '
                    'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (execution_id, playbook_id, playbook['version'], alert_id,
                     'PENDING', 1 if dry_run else 0, idempotency_key,
                     json.dumps(trigger), json.dumps(context),
                     json.dumps(evidence), None, now, now))
                for index, action in enumerate(plan['effective_actions']):
                    con.execute(
                        'INSERT INTO soar_execution_actions (execution_id, '
                        'action_index, action_type, state, parameters_json, '
                        'dry_run, attempts, created_at, updated_at) '
                        'VALUES (?,?,?,?,?,?,0,?,?)',
                        (execution_id, index, action['type'],
                         'WAITING_APPROVAL' if action['requires_approval']
                         else 'PENDING',
                         json.dumps(action['parameters']),
                         1 if (dry_run or action['dry_run']) else 0, now, now))
                _audit(con, execution_id=execution_id,
                       playbook_id=playbook_id, alert_id=alert_id,
                       actor=actor, event_type='execution_created',
                       from_state=None, to_state='PENDING', dry_run=dry_run,
                       result_json={'idempotency_key': idempotency_key,
                                    'dry_run': bool(dry_run)})
                con.commit()
            except sqlite3.IntegrityError:
                con.rollback()
                existing = self.get_execution_by_idempotency_key(
                    idempotency_key)
                if existing is not None:
                    raise DuplicateExecution(existing)
                raise
            except Exception:
                con.rollback()
                raise
        execution = self.get_execution(execution_id)
        if not dry_run:
            execution = self.advance(execution_id, actor=actor)
        return execution

    def recommend_execution(self, playbook_id, alert, ai_recommendation):
        """Record an AI-recommended execution — ALWAYS dry-run (5M).

        AI output can never start a real execution, satisfy an approval
        gate, or choose providers. This path stores the recommendation as
        data on a dry-run execution; only a human, through the normal
        approval/API path, can take it further. Secret-named keys in the
        recommendation are redacted before persistence.
        """
        if not isinstance(ai_recommendation, dict):
            raise SOARError('ai_recommendation must be an object')
        if len(json.dumps(ai_recommendation)) > MAX_TRIGGER_PAYLOAD_CHARS:
            raise SOARError('ai_recommendation exceeds maximum size')
        return self.start_execution(
            playbook_id, alert, dry_run=True, actor='ai-recommendation',
            ai_recommendation=redact_text(json.dumps(
                _redact_secret_keys(ai_recommendation), default=str))[:2000])

    def idempotency_key(self, playbook_id, playbook_version, alert_id,
                        correlation_id=None):
        """Deterministic dedupe key: playbook + version + alert context (5O)."""
        return hashlib.sha256(json.dumps(
            ['soar', playbook_id, playbook_version, alert_id, correlation_id],
            sort_keys=True).encode('utf-8')).hexdigest()

    def _load_investigation_package(self, alert_id):
        if alert_id is None:
            return {}
        from investigation import InvestigationError, InvestigationService
        try:
            return InvestigationService(self.db_file).build_investigation(alert_id)
        except InvestigationError:
            return {}
        except Exception:
            return {}

    def _load_ai_result(self, alert_id):
        if alert_id is None:
            return None
        try:
            from ai_investigation import AIInvestigationEngine
            result = AIInvestigationEngine(db_file=self.db_file) \
                .investigate(alert_id)
            return result if result.get('status') == 'ok' else None
        except Exception:
            return None

    # -- state machine core -------------------------------------------------

    def _set_state(self, con, execution_id, from_state, to_state, *, actor,
                   dry_run, error=None, event_type='state_transition'):
        allowed = EXECUTION_TRANSITIONS.get(from_state, set())
        if to_state not in allowed:
            raise InvalidStateTransition(from_state, to_state)
        con.execute(
            'UPDATE soar_executions SET state = ?, error = ?, updated_at = ? '
            'WHERE execution_id = ? AND state = ?',
            (to_state, redact_text(str(error))[:300] if error else None,
             utc_now(), execution_id, from_state))
        if con.total_changes is not None:
            changed = con.execute(
                'SELECT state FROM soar_executions WHERE execution_id = ?',
                (execution_id,)).fetchone()
            if changed is None or changed['state'] != to_state:
                raise InvalidStateTransition(from_state, to_state)
        _audit(con, execution_id=execution_id, actor=actor,
               event_type=event_type, from_state=from_state,
               to_state=to_state, dry_run=dry_run,
               failure_reason=error if to_state in TERMINAL_STATES else None)

    # -- driving an execution ------------------------------------------------

    def advance(self, execution_id, actor=AGENT):
        """Drive the execution as far as possible without external input.

        Handles validation, sequential action execution with retries and
        timeouts, and stops at approval gates. Returns the updated view.
        """
        execution = self.get_execution(execution_id)
        if execution is None:
            raise ExecutionNotFoundError(execution_id)
        if execution['state'] in TERMINAL_STATES:
            return execution
        dry_run = execution['dry_run']
        context = execution['context'] | {'execution_id': execution_id,
                                          'dry_run': dry_run}
        state = execution['state']

        if state == 'PENDING':
            with connect(self.db_file) as con:
                con.execute('BEGIN IMMEDIATE')
                try:
                    self._set_state(con, execution_id, 'PENDING', 'VALIDATING',
                                    actor=actor, dry_run=dry_run)
                    con.commit()
                except Exception:
                    con.rollback()
                    raise
            state = 'VALIDATING'

        if state == 'WAITING_APPROVAL':
            # Resume after a human decision: when no action is still gated,
            # move on to APPROVED; otherwise stay parked at the gate.
            still_gated = [a for a in self._execution_actions(execution_id)
                           if a['state'] == 'WAITING_APPROVAL']
            if still_gated:
                return execution
            with connect(self.db_file) as con:
                con.execute('BEGIN IMMEDIATE')
                try:
                    self._set_state(con, execution_id, 'WAITING_APPROVAL',
                                    'APPROVED', actor=actor, dry_run=dry_run)
                    con.commit()
                except Exception:
                    con.rollback()
                    raise
            state = 'APPROVED'

        if state == 'VALIDATING':
            try:
                self._validate_actions(execution)
            except ActionError as exc:
                return self._fail(execution_id, 'VALIDATING',
                                  'VALIDATION_FAILED', exc, actor, dry_run)
            actions = self._execution_actions(execution_id)
            pending_approval = next(
                (a for a in actions if a['state'] == 'WAITING_APPROVAL'), None)
            if pending_approval is not None:
                return self._pause_for_approval(execution_id, 'VALIDATING',
                                                actor, dry_run)
            with connect(self.db_file) as con:
                con.execute('BEGIN IMMEDIATE')
                try:
                    self._set_state(con, execution_id, 'VALIDATING', 'APPROVED',
                                    actor=actor, dry_run=dry_run)
                    con.commit()
                except Exception:
                    con.rollback()
                    raise
            state = 'APPROVED'

        if state == 'APPROVED':
            with connect(self.db_file) as con:
                con.execute('BEGIN IMMEDIATE')
                try:
                    self._set_state(con, execution_id, 'APPROVED', 'RUNNING',
                                    actor=actor, dry_run=dry_run)
                    con.commit()
                except Exception:
                    con.rollback()
                    raise
            state = 'RUNNING'

        if state == 'RUNNING':
            return self._run_actions(execution_id, execution, context, actor)

        return self.get_execution(execution_id)

    def _validate_actions(self, execution):
        for action in self._execution_actions(execution['execution_id']):
            provider = self.action_providers.get(action['action_type'])
            if provider is None:
                raise ActionError('validation_error',
                                  f"unknown action type {action['action_type']}")
            provider.validate(action['parameters'])

    def _pause_for_approval(self, execution_id, from_state, actor, dry_run):
        """Create missing approval rows, then move to WAITING_APPROVAL."""
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                rows = con.execute(
                    'SELECT action_index, action_type FROM '
                    'soar_execution_actions WHERE execution_id = ? AND '
                    "state = 'WAITING_APPROVAL' AND action_index NOT IN "
                    '(SELECT action_index FROM soar_approvals '
                    'WHERE execution_id = ?)',
                    (execution_id, execution_id)).fetchall()
                now = utc_now()
                for row in rows:
                    con.execute(
                        'INSERT INTO soar_approvals (approval_id, '
                        'execution_id, action_index, action_type, '
                        'requested_at, requester, decision, expires_at, '
                        'required_role) VALUES (?,?,?,?,?,?,?,?,?)',
                        (_short_hash('APR', ['approval', execution_id,
                                             row['action_index']]),
                         execution_id, row['action_index'], row['action_type'],
                         now, actor, 'pending',
                         self._expiry(now), 'analyst'))
                self._set_state(con, execution_id, from_state,
                                'WAITING_APPROVAL', actor=actor,
                                dry_run=dry_run)
                con.commit()
            except Exception:
                con.rollback()
                raise
        return self.get_execution(execution_id)

    def _expiry(self, now, minutes=DEFAULT_APPROVAL_TTL_MINUTES):
        from datetime import datetime, timedelta
        moment = datetime.fromisoformat(now.replace('Z', '+00:00'))
        return (moment + timedelta(
            minutes=max(1, min(int(minutes), MAX_TTL_MINUTES)))
        ).isoformat(timespec='microseconds').replace('+00:00', 'Z')

    def _run_actions(self, execution_id, execution, context, actor):
        """Execute actions sequentially with retries, bounds, and audit."""
        dry_run = execution['dry_run']
        while True:
            execution = self.get_execution(execution_id)
            if execution['state'] != 'RUNNING':
                return execution
            actions = self._execution_actions(execution_id)
            gate = next((a for a in actions
                         if a['state'] == 'WAITING_APPROVAL'), None)
            if gate is not None:
                return self._pause_for_approval(execution_id, 'RUNNING',
                                                actor, dry_run)
            pending = next((a for a in actions
                            if a['state'] in ('PENDING', 'APPROVED')), None)
            if pending is None:
                with connect(self.db_file) as con:
                    con.execute('BEGIN IMMEDIATE')
                    try:
                        self._set_state(con, execution_id, 'RUNNING',
                                        'SUCCEEDED', actor=actor,
                                        dry_run=dry_run)
                        con.commit()
                    except Exception:
                        con.rollback()
                        raise
                return self.get_execution(execution_id)
            outcome = self._execute_one(execution_id, execution, pending,
                                        context, actor)
            if outcome in ('failed', 'timed_out'):
                return self.get_execution(execution_id)

    def _execute_one(self, execution_id, execution, action, context, actor):
        """Run one action attempt with retry bounds; returns 'ok'/'failed'."""
        dry_run = execution['dry_run']
        provider = self.action_providers[action['action_type']]
        plan = self.policy_engine.evaluate(
            self.get_execution_definition(execution))
        max_attempts = max(1, min(plan.get('max_attempts', 1), 4))
        action_context = context | {
            'action_index': action['action_index'],
            'correlation_id': execution['context'].get('correlation_id'),
            'incident_service': self.incident_service,
            'evidence': execution.get('evidence'),
            'evidence_id': (execution.get('evidence') or {}).get('evidence_id'),
        }
        attempts = action['attempts']
        while attempts < max_attempts:
            attempts += 1
            started = utc_now()
            try:
                result = provider.execute(action['parameters'], action_context,
                                          dry_run=bool(action['dry_run']))
                result = json.loads(redact_text(json.dumps(
                    result, default=str)))
                with connect(self.db_file) as con:
                    con.execute('BEGIN IMMEDIATE')
                    try:
                        con.execute(
                            'UPDATE soar_execution_actions SET state = ?, '
                            'attempts = ?, result_json = ?, error = NULL, '
                            'updated_at = ? WHERE execution_id = ? AND '
                            'action_index = ?',
                            ('SUCCEEDED', attempts, json.dumps(result)[:6000],
                             utc_now(), execution_id, action['action_index']))
                        _audit(con, execution_id=execution_id,
                               playbook_id=execution['playbook_id'],
                               action_index=action['action_index'],
                               alert_id=execution['alert_id'], actor=actor,
                               event_type='action_succeeded',
                               from_state='RUNNING', to_state='SUCCEEDED',
                               dry_run=bool(action['dry_run']),
                               result_json=result)
                        con.commit()
                    except Exception:
                        con.rollback()
                        raise
                return 'ok'
            except ActionError as exc:
                self._record_attempt_failure(execution_id, execution, action,
                                             attempts, exc, actor)
                retryable = (exc.category not in ('validation_error',
                                                  'not_supported',
                                                  'cancelled'))
                if not retryable or attempts >= max_attempts:
                    self._fail_action(execution_id, action, exc, actor,
                                      dry_run)
                    return 'failed'
                # Controlled retry: loop continues after recording failure.
            except Exception as exc:  # unexpected provider crash
                bounded = ActionError('provider_error', f'{type(exc).__name__}')
                self._record_attempt_failure(execution_id, execution, action,
                                             attempts, bounded, actor)
                if attempts >= max_attempts:
                    self._fail_action(execution_id, action, bounded, actor,
                                      dry_run)
                    return 'failed'
        return 'failed'

    def _record_attempt_failure(self, execution_id, execution, action,
                                attempts, exc, actor):
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                con.execute(
                    'UPDATE soar_execution_actions SET attempts = ?, '
                    'error = ?, updated_at = ? WHERE execution_id = ? AND '
                    'action_index = ?',
                    (attempts,
                     json.dumps({'category': exc.category,
                                 'message': exc.message})[:600],
                     utc_now(), execution_id, action['action_index']))
                _audit(con, execution_id=execution_id,
                       playbook_id=execution['playbook_id'],
                       action_index=action['action_index'],
                       alert_id=execution['alert_id'], actor=actor,
                       event_type='action_attempt_failed',
                       from_state='RUNNING', to_state='RUNNING',
                       dry_run=bool(action['dry_run']),
                       failure_reason=f'{exc.category}: {exc.message}',
                       result_json={'attempt': attempts})
                con.commit()
            except Exception:
                con.rollback()
                raise

    def _fail_action(self, execution_id, action, exc, actor, dry_run):
        execution = self.get_execution(execution_id)
        failure_policy = self._failure_policy(execution)
        playbook_id = execution['playbook_id']
        alert_id = execution['alert_id']
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                con.execute(
                    'UPDATE soar_execution_actions SET state = ?, '
                    'updated_at = ? WHERE execution_id = ? AND action_index = ?',
                    ('FAILED', utc_now(), execution_id, action['action_index']))
                to_state = ('ACTION_FAILED' if failure_policy == 'stop'
                            else 'RUNNING')
                self._set_state(con, execution_id, 'RUNNING', to_state,
                                actor=actor, dry_run=dry_run,
                                error=f'{exc.category}: {exc.message}',
                                event_type='action_failed')
                con.commit()
            except InvalidStateTransition:
                con.rollback()
                raise
            except Exception:
                con.rollback()
                raise

    def _failure_policy(self, execution):
        definition = self._definition_for_execution(execution)
        return definition.get('failure_policy', 'stop')

    def _definition_for_execution(self, execution):
        playbook_id = execution['playbook_id']
        playbook = self.get_playbook(playbook_id)
        definition = playbook['definition'] if playbook else {}
        # Pin the exact version recorded on the execution when available.
        version = execution.get('playbook_version')
        if version is not None and definition.get('version') != version \
                and playbook:
            definition = dict(definition)
        return definition

    def get_execution_definition(self, execution):
        return self._definition_for_execution(execution)

    # -- approvals (5E) -------------------------------------------------------

    def list_approvals(self, decision=None, limit=50):
        limit = max(1, min(int(limit), MAX_LIST_LIMIT))
        query = ('SELECT approval_id, execution_id, action_index, action_type, '
                 'requested_at, requester, approver, decision, decided_at, '
                 'reason, expires_at, required_role FROM soar_approvals ')
        params = []
        if decision:
            if decision not in ('pending', 'approved', 'rejected', 'expired',
                                'cancelled'):
                raise SOARError('invalid decision filter')
            query += 'WHERE decision = ? '
            params.append(decision)
        query += 'ORDER BY requested_at DESC, approval_id LIMIT ?'
        params.append(limit)
        with connect(self.db_file) as con:
            rows = con.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def decide_approval(self, approval_id, decision, approver, reason=None):
        """Record a human approval decision; drives the execution onward.

        ``approver`` must be a bounded logical username. AI output can never
        reach this path: decisions arrive only through authenticated API
        calls or explicit local admin actions.
        """
        if decision not in ('approved', 'rejected'):
            raise SOARError("decision must be 'approved' or 'rejected'")
        if not isinstance(approver, str) or not USER_ACTOR_RE.match(approver):
            raise SOARError('approver must be a bounded logical username')
        reason = redact_text(str(reason or ''))[:300]
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                row = con.execute(
                    'SELECT approval_id, execution_id, action_index, decision, '
                    'expires_at, required_role FROM soar_approvals '
                    'WHERE approval_id = ?', (approval_id,)).fetchone()
                if row is None:
                    raise ApprovalNotFoundError(approval_id)
                if row['decision'] != 'pending':
                    raise InvalidStateTransition(row['decision'], decision)
                if self._is_expired(row['expires_at']):
                    con.execute(
                        'UPDATE soar_approvals SET decision = ?, '
                        "decided_at = ? WHERE approval_id = ?",
                        ('expired', utc_now(), approval_id))
                    con.commit()
                    raise ApprovalExpiredError(approval_id)
                con.execute(
                    'UPDATE soar_approvals SET decision = ?, approver = ?, '
                    'decided_at = ?, reason = ? WHERE approval_id = ?',
                    (decision, approver, utc_now(), reason, approval_id))
                con.commit()
            except Exception:
                con.rollback()
                raise
        execution_id = row['execution_id']
        execution = self.get_execution(execution_id)
        if decision == 'rejected':
            with connect(self.db_file) as con:
                con.execute('BEGIN IMMEDIATE')
                try:
                    con.execute(
                        'UPDATE soar_execution_actions SET state = ? , '
                        'updated_at = ? WHERE execution_id = ? AND '
                        'action_index = ?',
                        ('CANCELLED', utc_now(), execution_id,
                         row['action_index']))
                    self._set_state(con, execution_id, execution['state'],
                                    'APPROVAL_REJECTED', actor=approver,
                                    dry_run=execution['dry_run'],
                                    error=f'approval {approval_id} rejected',
                                    event_type='approval_decision')
                    con.commit()
                except Exception:
                    con.rollback()
                    raise
            return self.get_execution(execution_id)
        # approved: mark the action APPROVED and continue the execution.
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                con.execute(
                    'UPDATE soar_execution_actions SET state = ?, '
                    'updated_at = ? WHERE execution_id = ? AND action_index = ?',
                    ('APPROVED', utc_now(), execution_id, row['action_index']))
                _audit(con, execution_id=execution_id,
                       playbook_id=execution['playbook_id'],
                       action_index=row['action_index'],
                       alert_id=execution['alert_id'], actor=approver,
                       event_type='approval_decision',
                       from_state='pending', to_state='approved',
                       dry_run=execution['dry_run'],
                       approval_state='approved')
                con.commit()
            except Exception:
                con.rollback()
                raise
        return self.advance(execution_id, actor=approver)

    def _is_expired(self, expires_at):
        from datetime import datetime
        moment = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        now = datetime.fromisoformat(utc_now().replace('Z', '+00:00'))
        return now >= moment

    def expire_stale_approvals(self):
        """Mark past-TTL pending approvals expired (deterministic sweep)."""
        expired = []
        with connect(self.db_file) as con:
            rows = con.execute(
                "SELECT approval_id, execution_id, expires_at FROM "
                "soar_approvals WHERE decision = 'pending'").fetchall()
        for row in rows:
            if self._is_expired(row['expires_at']):
                with connect(self.db_file) as con:
                    con.execute('BEGIN IMMEDIATE')
                    try:
                        con.execute(
                            'UPDATE soar_approvals SET decision = ?, '
                            'decided_at = ? WHERE approval_id = ? AND '
                            "decision = 'pending'",
                            ('expired', utc_now(), row['approval_id']))
                        execution = self.get_execution(row['execution_id'])
                        if execution and execution['state'] == \
                                'WAITING_APPROVAL':
                            self._set_state(
                                con, row['execution_id'], 'WAITING_APPROVAL',
                                'APPROVAL_EXPIRED', actor=AGENT,
                                dry_run=execution['dry_run'],
                                error='approval expired',
                                event_type='approval_expired')
                        con.commit()
                    except Exception:
                        con.rollback()
                        raise
                expired.append(row['approval_id'])
        return expired

    # -- cancellation / timeout (5P) ------------------------------------------

    def cancel_execution(self, execution_id, actor, reason=None):
        """Cancel a non-terminal execution; later actions never run."""
        if not isinstance(actor, str) or not USER_ACTOR_RE.match(actor):
            raise SOARError('actor must be a bounded logical username')
        execution = self.get_execution(execution_id)
        if execution is None:
            raise ExecutionNotFoundError(execution_id)
        reason = redact_text(str(reason or ''))[:300]
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                con.execute(
                    "UPDATE soar_execution_actions SET state = 'CANCELLED', "
                    'updated_at = ? WHERE execution_id = ? AND state IN '
                    "('PENDING', 'WAITING_APPROVAL', 'APPROVED')",
                    (utc_now(), execution_id))
                con.execute(
                    "UPDATE soar_approvals SET decision = 'cancelled', "
                    'decided_at = ? WHERE execution_id = ? AND '
                    "decision = 'pending'", (utc_now(), execution_id))
                self._set_state(con, execution_id, execution['state'],
                                'CANCELLED', actor=actor,
                                dry_run=execution['dry_run'],
                                error=f'cancelled: {reason}',
                                event_type='execution_cancelled')
                con.commit()
            except Exception:
                con.rollback()
                raise
        return self.get_execution(execution_id)

    # -- queries ---------------------------------------------------------------

    def get_execution(self, execution_id):
        with connect(self.db_file) as con:
            row = con.execute(
                'SELECT execution_id, playbook_id, playbook_version, alert_id, '
                'state, dry_run, idempotency_key, trigger_json, context_json, '
                'evidence_json, error, created_at, updated_at '
                'FROM soar_executions WHERE execution_id = ?',
                (execution_id,)).fetchone()
        return self._execution_view(row) if row else None

    def get_execution_by_idempotency_key(self, key):
        with connect(self.db_file) as con:
            row = con.execute(
                'SELECT execution_id FROM soar_executions WHERE '
                'idempotency_key = ?', (key,)).fetchone()
        return self.get_execution(row['execution_id']) if row else None

    def list_executions(self, limit=50, alert_id=None):
        limit = max(1, min(int(limit), MAX_LIST_LIMIT))
        query = ('SELECT execution_id, playbook_id, playbook_version, '
                 'alert_id, state, dry_run, created_at, updated_at, error '
                 'FROM soar_executions ')
        params = []
        if alert_id is not None:
            query += 'WHERE alert_id = ? '
            params.append(alert_id)
        query += 'ORDER BY created_at DESC, execution_id LIMIT ?'
        params.append(limit)
        with connect(self.db_file) as con:
            rows = con.execute(query, params).fetchall()
        return [dict(row) | {'dry_run': bool(row['dry_run'])}
                for row in rows]

    def list_audit(self, execution_id=None, limit=100):
        limit = max(1, min(int(limit), MAX_LIST_LIMIT))
        query = ('SELECT id, execution_id, playbook_id, action_index, '
                 'alert_id, actor, event_type, from_state, to_state, dry_run, '
                 'approval_state, result_json, failure_reason, created_at '
                 'FROM soar_audit ')
        params = []
        if execution_id:
            query += 'WHERE execution_id = ? '
            params.append(execution_id)
        query += 'ORDER BY id DESC LIMIT ?'
        params.append(limit)
        with connect(self.db_file) as con:
            rows = con.execute(query, params).fetchall()
        views = []
        for row in rows:
            view = dict(row)
            view['dry_run'] = bool(view['dry_run'])
            if view['result_json']:
                view['result'] = json.loads(view.pop('result_json'))
            else:
                view.pop('result_json')
            views.append(view)
        return views

    def _execution_view(self, row):
        view = dict(row)
        view['dry_run'] = bool(view['dry_run'])
        view['trigger'] = json.loads(view.pop('trigger_json'))
        view['context'] = json.loads(view.pop('context_json'))
        if view['evidence_json']:
            view['evidence'] = json.loads(view.pop('evidence_json'))
        else:
            view.pop('evidence_json')
        return view

    def _execution_actions(self, execution_id):
        with connect(self.db_file) as con:
            rows = con.execute(
                'SELECT action_index, action_type, state, parameters_json, '
                'dry_run, attempts, result_json, error, created_at, '
                'updated_at FROM soar_execution_actions WHERE execution_id = ? '
                'ORDER BY action_index', (execution_id,)).fetchall()
        views = []
        for row in rows:
            view = dict(row)
            view['parameters'] = json.loads(view.pop('parameters_json'))
            view['dry_run'] = bool(view['dry_run'])
            if view['result_json']:
                view['result'] = json.loads(view.pop('result_json'))
            else:
                view.pop('result_json')
            views.append(view)
        return views

    def _all_attempts(self, execution_id):
        actions = self._execution_actions(execution_id)
        return [a['attempts'] for a in actions if a['attempts']]

    def _fail(self, execution_id, from_state, to_state, exc, actor, dry_run):
        with connect(self.db_file) as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                self._set_state(con, execution_id, from_state, to_state,
                                actor=actor, dry_run=dry_run,
                                error=f'{exc.category}: {exc.message}',
                                event_type='validation_failed')
                con.commit()
            except Exception:
                con.rollback()
                raise
        return self.get_execution(execution_id)
