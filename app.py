"""Local ThreatWatch dashboard and authenticated event-ingest API."""
from collections import deque
import hmac
import json
import logging
import os
import sqlite3
import threading
import time

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from database import DB, EventIdConflictError, connect, init_db, utc_now
from detector import process_event
from embeddings import make_indexing_provider
from event_model import EventValidationError, SecurityEvent
from hunting import HuntError, hunt
from investigation import InvestigationError, InvestigationService
from investigation_provider import apply_investigation_provider, make_investigation_provider
from ai_hunting import AIHuntError, execute_ai_hunt
from ai_investigation import AIInvestigationEngine, AI_SCHEMA_VERSION
from llm_provider import make_llm_provider
from retrieval import KnowledgeRetriever, RetrievalError
from vector_store import KNOWLEDGE_DB_DEFAULT, VectorStore

from security_config import load_ingest_token, validate_ingest_token
from soar import (ApprovalExpiredError, ApprovalNotFoundError,
                  DuplicateExecution, ExecutionNotFoundError,
                  PlaybookNotFoundError, SOAREngine, SOARError,
                  USER_ACTOR_RE)
from rules import load_rules
import soc_simulation

logger = logging.getLogger('threatwatch.api')
MAX_INGEST_REQUESTS_PER_MINUTE = 120
MAX_CONTENT_LENGTH = 1024 * 1024


class IngestRateLimiter:
    """Small process-local limit for the local demo ingestion route."""

    def __init__(self, limit=MAX_INGEST_REQUESTS_PER_MINUTE, window=60):
        self.limit = limit
        self.window = window
        self.requests = {}
        self.lock = threading.Lock()

    def allow(self, client):
        now = time.monotonic()
        with self.lock:
            requests = self.requests.setdefault(client, deque())
            while requests and requests[0] <= now - self.window:
                requests.popleft()
            if len(requests) >= self.limit:
                return False
            requests.append(now)
            if len(self.requests) > 1024:
                self.requests = {
                    key: values for key, values in self.requests.items()
                    if values and values[-1] > now - self.window
                }
            return True


def _alert_hostnames(alert, db_file=None):
    """Hostnames for one alert, read from its actual contributing events.

    Complements evidence-derived entities: some findings (e.g. the windowed
    brute-force rule) do not carry the target hostname in their evidence, so
    the analyst view reads it from the stored source events instead.
    """
    if alert.get('hostnames'):
        return alert['hostnames']
    event_ids = alert.get('source_event_ids') or []
    if not event_ids:
        return []
    placeholders = ','.join('?' for _ in event_ids)
    with connect(db_file) as connection:
        rows = connection.execute(
            f'SELECT DISTINCT host FROM events WHERE event_id IN ({placeholders}) '
            "AND host IS NOT NULL AND host != ''",
            event_ids).fetchall()
    return sorted({row[0] for row in rows})[:20]


SOC_ALERT_FIELDS = (
    'detection_id', 'rule_id', 'deterministic_risk_score', 'risk_band',
    'risk_factors_json', 'risk_explanation', 'jev_priority', 'jev_malicious_likelihood',
    'jev_false_positive_likelihood', 'jev_investigation_required',
    'jev_attack_category', 'jev_status', 'mitre_techniques_json',
    'evidence_json', 'source_event_ids_json', 'correlation_id',
    'investigation_status',
)


def _soc_alert_fields(row):
    """Flatten the SOC columns of one alerts row into JSON-safe values."""
    fields = {}
    for name in SOC_ALERT_FIELDS:
        value = row[name]
        if name.endswith('_json'):
            try:
                value = json.loads(value) if value is not None else None
            except (TypeError, ValueError):
                value = None
            fields[name[:-5]] = value
        elif name == 'jev_investigation_required':
            fields['investigation_required'] = bool(value) if value is not None else None
        else:
            fields[name] = value
    return fields


def get_alerts(limit=200, db_file=None):
    with connect(db_file or DB) as connection:
        columns = ', '.join(('id', 'time', 'rule', 'severity', 'details') + SOC_ALERT_FIELDS)
        rows = connection.execute(
            f'SELECT {columns} FROM alerts ORDER BY id DESC LIMIT ?',
            (limit,),
        ).fetchall()
    alerts = []
    for row in rows:
        alert = {
            'id': row['id'], 'time': row['time'], 'rule': row['rule'],
            'severity': row['severity'], 'details': row['details'],
        }
        alert.update(_soc_alert_fields(row))
        alert.update(_alert_entity_fields(alert))
        alerts.append(alert)
    return alerts


def get_alerts_with_hostnames(limit=200, db_file=None):
    """Alert queue rows with event-derived hostnames filled in."""
    alerts = get_alerts(limit=limit, db_file=db_file)
    for alert in alerts:
        alert['hostnames'] = _alert_hostnames(alert, db_file=db_file)
    return alerts


# -- Phase 3 investigation lifecycle ------------------------------------
# Canonical states with a deterministic transition matrix. Phase 2 input
# values ('in_progress', 'closed') remain accepted as aliases and are
# canonicalized before storage; arbitrary values are always rejected.
INVESTIGATION_STATUSES = ('new', 'investigating', 'resolved', 'dismissed')
STATUS_ALIASES = {'in_progress': 'investigating', 'closed': 'resolved'}

ALLOWED_TRANSITIONS = {
    'new': frozenset({'new', 'investigating', 'resolved', 'dismissed'}),
    'investigating': frozenset({'investigating', 'resolved', 'dismissed'}),
    'resolved': frozenset({'investigating', 'dismissed'}),
    'dismissed': frozenset({'investigating'}),
}


class InvestigationTransitionError(ValueError):
    """A lifecycle transition that the deterministic matrix forbids."""


def canonical_investigation_status(status):
    """Map a requested status (or Phase 2 alias) to its canonical value."""
    if not isinstance(status, str):
        raise ValueError('investigation status must be a string')
    value = STATUS_ALIASES.get(status.strip().lower(), status.strip().lower())
    if value not in INVESTIGATION_STATUSES:
        raise ValueError('invalid investigation status')
    return value


def get_investigation_status(alert_id, db_file=None):
    with connect(db_file or DB) as connection:
        row = connection.execute(
            'SELECT investigation_status FROM alerts WHERE id = ?',
            (alert_id,)).fetchone()
    return row['investigation_status'] if row else None


def set_investigation_status(alert_id, status, db_file=None, source='api'):
    """Apply one lifecycle transition atomically and audit it.

    Raises ValueError for unknown states and InvestigationTransitionError
    for transitions the matrix forbids. Every accepted transition writes an
    investigation_events audit row before committing.
    """
    target = canonical_investigation_status(status)
    with connect(db_file or DB) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            row = connection.execute(
                'SELECT investigation_status FROM alerts WHERE id = ?',
                (alert_id,)).fetchone()
            if row is None:
                connection.rollback()
                return False
            current = row['investigation_status']
            # Tolerate pre-Phase-3 stored values when checking the matrix.
            current_canonical = STATUS_ALIASES.get(current, current)
            if current_canonical not in ALLOWED_TRANSITIONS:
                current_canonical = 'new'
            if target not in ALLOWED_TRANSITIONS[current_canonical]:
                connection.rollback()
                raise InvestigationTransitionError(
                    f'transition {current_canonical} -> {target} is not allowed')
            connection.execute(
                'UPDATE alerts SET investigation_status = ? WHERE id = ?',
                (target, alert_id),
            )
            connection.execute(
                'INSERT INTO investigation_events '
                '(alert_id, from_status, to_status, changed_at, source) '
                'VALUES (?, ?, ?, ?, ?)',
                (alert_id, current, target, utc_now(), source),
            )
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise


import re


def _extract_ips(value):
    """Extract bounded IPv4/IPv6 candidates from free text (evidence search)."""
    if not isinstance(value, str):
        return []
    return re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', value)[:10]


def _answer_alert_question(question, alert_id, db_file=None):
    """Deterministic, evidence-bounded answers to analyst questions.

    Questions map to supported investigation operations only; there is no
    chat model, no SQL, no commands, and no configuration access. When the
    stored evidence cannot answer the question, the response is
    INSUFFICIENT_EVIDENCE rather than speculation.
    """
    service = InvestigationService(db_file=db_file)
    package = service.build_investigation(alert_id)
    evidence = package.get('evidence') or {}
    entities = evidence.get('entities') or {}
    timeline = (package.get('timeline') or {}).get('entries') or []
    related = ((package.get('related_alerts') or {}).get('alerts')) or []
    intel_matches = ((package.get('threat_intel') or {}).get('matches')) or []
    norm = question.lower()
    sources = sorted({ip for ip in (entities.get('source_ips') or [])})
    users = sorted({u for u in (entities.get('affected_users') or [])
                    if u and u != 'unknown'})
    question_sources = [ip for ip in _extract_ips(question) if ip in set(sources)]
    focus_sources = question_sources or sources

    if any(term in norm for term in ('source ip', 'attacked', 'other account',
                                     'other accounts', 'same source',
                                     'same ip', 'this ip')):
        if not focus_sources:
            return {'answer': 'INSUFFICIENT_EVIDENCE', 'basis': [
                'No source IP is recorded for this alert.'],
                'sources_checked': []}
        try:
            result = hunt({'src_ip': focus_sources[0]}, db_file=db_file,
                          limit=100)
        except HuntError as exc:
            return {'answer': 'INSUFFICIENT_EVIDENCE', 'basis': [str(exc)[:300]],
                    'sources_checked': focus_sources}
        events = result.get('results') if isinstance(result, dict) else result
        events = events or []
        target_users = {event.get('user') for event in events if event.get('user')}
        target_users.discard('unknown')
        other_accounts = sorted(target_users - set(users))
        basis = [
            f"deterministic hunt: {len(events)} stored events from "
            f"{focus_sources[0]}",
            f"accounts seen: {sorted(target_users) or ['none']}",
            f"accounts on this alert: {users or ['none']}",
        ]
        if other_accounts:
            answer = (f"Yes — source {focus_sources[0]} also appears against "
                      f"{len(other_accounts)} other account(s): "
                      f"{', '.join(other_accounts)}.")
        elif events:
            accounts_label = users or ["this alert's accounts"]
            answer = (f"No — stored evidence shows source {focus_sources[0]} "
                      f"only against {accounts_label}.")
        else:
            answer = 'INSUFFICIENT_EVIDENCE'
        return {'answer': answer, 'basis': basis,
                'sources_checked': focus_sources,
                'related_alert_count': len(related)}

    if any(term in norm for term in ('timeline', 'what happened', 'chronology',
                                     'sequence')):
        if not timeline:
            return {'answer': 'INSUFFICIENT_EVIDENCE', 'basis': [
                'No timeline entries are stored for this alert.'],
                'sources_checked': []}
        lines = [f"{entry.get('timestamp', '?')} {entry.get('event_type', '?')}"
                 f"{(' from ' + entry['src_ip']) if entry.get('src_ip') else ''}"
                 f"{(' user ' + entry['user']) if entry.get('user') else ''}"
                 for entry in timeline[:5]]
        return {'answer': 'Timeline (deterministic evidence): ' + ' | '.join(lines),
                'basis': [f'{len(timeline)} stored timeline entries'],
                'sources_checked': focus_sources}

    if any(term in norm for term in ('threat intel', 'intel', 'known',
                                     'malicious ip', 'blocklist')):
        if intel_matches:
            lines = [f"{match.get('indicator_type')} {match.get('indicator')} "
                     f"known={match.get('known_malicious')} "
                     f"(confidence {match.get('confidence')})"
                     for match in intel_matches[:5]]
            return {'answer': 'Threat intel (deterministic): ' + ' | '.join(lines),
                    'basis': [f'{len(intel_matches)} stored intel match(es)'],
                    'sources_checked': focus_sources}
        return {'answer': 'No threat-intelligence match is recorded for this '
                          'alert\'s indicators.',
                'basis': ['stored enrichment contains no matching indicators'],
                'sources_checked': focus_sources}

    if any(term in norm for term in ('related alert', 'correlation', 'other alert',
                                     'linked alert')):
        if related:
            lines = [f"#{alert.get('alert_id')} {alert.get('rule')} "
                     f"({alert.get('severity')}, {alert.get('relation')})"
                     for alert in related[:5]]
            return {'answer': 'Related alerts (deterministic): ' + ' | '.join(lines),
                    'basis': [f'{len(related)} related alert(s) stored'],
                    'sources_checked': focus_sources}
        return {'answer': 'No related alerts are stored for this alert.',
                'basis': ['correlation index has no linked alerts'],
                'sources_checked': focus_sources}

    if any(term in norm for term in ('who', 'user', 'account', 'identity')):
        if users or sources:
            parts = []
            if users:
                parts.append('accounts: ' + ', '.join(users))
            if sources:
                parts.append('source IPs: ' + ', '.join(sources))
            return {'answer': 'Entities in stored evidence — ' + '; '.join(parts) + '.',
                    'basis': ['alert evidence entities'],
                    'sources_checked': sources}
        return {'answer': 'INSUFFICIENT_EVIDENCE',
                'basis': ['no user or source entities stored'], 'sources_checked': []}

    return {'answer': 'INSUFFICIENT_EVIDENCE',
            'basis': ['question did not map to a supported evidence query; '
                      'supported: source-IP activity, timeline, threat intel, '
                      'related alerts, involved accounts'],
            'sources_checked': sources}


def playbook_matches_alert(definition, alert, intel_match=False):
    """True when the alert satisfies any of the playbook's declarative
    triggers. Mirrors ``playbook.playbook_matches`` using the stored alert
    row (the SOAR engine applies the same logic at execution start; this
    read-only mirror only powers preview suggestions and never bypasses it).
    """
    severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
    priority_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    priority_of = None
    jev = alert.get('jev_priority')
    if isinstance(jev, str):
        priority_of = priority_order.get(jev.strip().lower())
    for trigger in definition.get('triggers') or []:
        kind = trigger.get('type')
        operator = trigger.get('operator', 'equals')
        value = trigger.get('value')
        values = value if isinstance(value, list) else [value]

        def op(actual):
            if actual is None:
                return False
            if operator == 'equals':
                return actual == value
            if operator == 'not_equals':
                return actual != value
            if operator == 'in':
                return actual in values
            if operator == 'not_in':
                return actual not in values
            return False

        if kind == 'alert_created':
            return True
        if kind == 'rule_id' and op(alert.get('rule_id')):
            return True
        if kind == 'attack_category' and op(alert.get('attack_category')):
            return True
        if kind == 'investigation_status' and op(alert.get('investigation_status')):
            return True
        if kind == 'severity_at_least':
            floor = severity_order.get(str(value).upper(), 0)
            actual = severity_order.get(alert.get('severity') or '', 0)
            if floor and actual >= floor:
                return True
        if kind == 'priority_at_least' and priority_of is not None:
            floor = priority_order.get(str(value).lower(), 0)
            if floor and priority_of >= floor:
                return True
        if kind == 'threat_intel_match' and intel_match:
            return True
    return False


def _alert_has_intel(alert_id, db_file=None):
    with connect(db_file or DB) as connection:
        row = connection.execute(
            'SELECT value FROM alert_enrichment WHERE alert_id = ? AND key = ?',
            (alert_id, 'known_threat')).fetchone()
    return bool(row and str(row['value']).lower() == 'true')


def _alert_entity_fields(alert, connection=None):
    """Derive analyst-facing entity columns from the alert's stored evidence.

    ``evidence_json`` is the raw correlation evidence written by the detector
    (correlator merge keys at the top level: source_ips, affected_users,
    affected_hosts, processes, command_lines, …), so it is the authoritative
    entity source — never reconstructed client-side.
    """
    evidence = alert.get('evidence')
    if not isinstance(evidence, dict):
        evidence = {}
    entities = evidence.get('entities') if isinstance(
        evidence.get('entities'), dict) else evidence

    def _values(key, skip_unknown=True):
        values = entities.get(key)
        if values is None:
            values = []
        elif not isinstance(values, list):
            values = [values]  # single-finding evidence stores scalars
        cleaned = {str(value) for value in values if value}
        if skip_unknown:
            cleaned.discard('unknown')
        return sorted(cleaned)[:20]

    source_ips = _values('source_ips') or _values('source_ip', skip_unknown=False)
    users = _values('affected_users') or _values('username', skip_unknown=False)
    hosts = _values('affected_hosts') or _values('hostname')
    processes = _values('processes') or _values('process_name', skip_unknown=False)
    categories = {alert.get('jev_attack_category')} - {None, ''}
    return {
        'attack_category': sorted(categories)[0] if categories else None,
        'source_ips': source_ips,
        'affected_users': users,
        'hostnames': hosts,
        'processes': processes,
        'command_lines': _values('command_lines', skip_unknown=False)
        or _values('command_line', skip_unknown=False),
    }


def _clear_pipeline_state(db_file):
    """Reset rate/suppression state so a scenario behaves like a cold start.

    Deletes accumulated failed-login windows and duplicate-alert suppression
    rows (rate-limit state, not evidence). Used by the full-validation and
    demo endpoints so each scenario runs exactly as a freshly started
    instance would; never invoked by the ordinary ingest path.
    """
    with connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        connection.execute('DELETE FROM failed_login_attempts')
        connection.execute('DELETE FROM alert_suppression')
        connection.commit()


def create_app(config=None):
    application = Flask(__name__)
    application.config.update(
        DB_FILE=DB,
        INGEST_TOKEN=load_ingest_token(),
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        KNOWLEDGE_DB_FILE=KNOWLEDGE_DB_DEFAULT,
        TESTING=False,
    )
    if config:
        application.config.update(config)
    application.config['INGEST_TOKEN'] = validate_ingest_token(
        application.config.get('INGEST_TOKEN'))
    init_db(application.config['DB_FILE'])
    application.extensions['ingest_rate_limiter'] = IngestRateLimiter()

    @application.after_request
    def add_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        response.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'",
        )
        if request.path.startswith('/api/'):
            response.headers.setdefault('Cache-Control', 'no-store')
        return response

    @application.errorhandler(BadRequest)
    def bad_request(_error):
        return jsonify(error='invalid_json'), 400

    @application.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return jsonify(error='payload_too_large'), 413

    @application.get('/')
    def index():
        return render_template('dashboard.html')

    @application.get('/api/alerts')
    def api_alerts():
        return jsonify(get_alerts(db_file=application.config['DB_FILE']))

    @application.get('/api/summary')
    def api_summary():
        alerts = get_alerts(1000, application.config['DB_FILE'])
        summary = {}
        for alert in alerts:
            summary[alert['rule']] = summary.get(alert['rule'], 0) + 1
        return jsonify(summary)

    @application.get('/api/health')
    def api_health():
        return jsonify(status='ok')

    @application.post('/api/alerts/<int:alert_id>/status')
    def api_alert_status(alert_id):
        expected = application.config.get('INGEST_TOKEN')
        if not expected:
            return jsonify(error='authentication_disabled'), 503
        authorization = request.headers.get('Authorization', '')
        scheme, separator, supplied = authorization.partition(' ')
        if scheme.lower() != 'bearer' or not separator or not supplied:
            return jsonify(error='authentication_required'), 401, {'WWW-Authenticate': 'Bearer'}
        if not hmac.compare_digest(supplied.encode('utf-8'), expected.encode('utf-8')):
            return jsonify(error='invalid_credentials'), 401, {'WWW-Authenticate': 'Bearer'}
        body = request.get_json(silent=True)
        try:
            requested = canonical_investigation_status(
                body.get('status') if isinstance(body, dict) else None)
        except ValueError:
            return jsonify(error='invalid_status'), 400
        try:
            updated = set_investigation_status(
                alert_id, requested, db_file=application.config['DB_FILE'])
        except InvestigationTransitionError:
            return jsonify(error='invalid_transition'), 409
        except sqlite3.Error:
            logger.exception('Investigation status update failed')
            return jsonify(error='storage_unavailable'), 503
        if not updated:
            return jsonify(error='alert_not_found'), 404
        return jsonify(alert_id=alert_id, status=requested)

    @application.get('/api/alerts/<int:alert_id>/timeline')
    def api_alert_timeline(alert_id):
        service = InvestigationService(db_file=application.config['DB_FILE'])
        try:
            package = service.build_investigation(alert_id)
        except InvestigationError:
            return jsonify(error='alert_not_found'), 404
        return jsonify({
            'alert_id': alert_id,
            'correlation_id': package['alert'].get('correlation_id'),
            'timeline': package['timeline'],
        })

    @application.get('/api/hunt')
    def api_hunt():
        filters = {key: value for key, value in request.args.items()
                   if key not in ('limit', 'offset')}
        try:
            results = hunt(
                filters,
                db_file=application.config['DB_FILE'],
                limit=request.args.get('limit', 100),
                offset=request.args.get('offset', 0),
            )
        except HuntError as exc:
            return jsonify(error='invalid_hunt_query', message=str(exc)), 400
        return jsonify(results)

    # -- Phase 4: knowledge retrieval (read-only; index writes stay local) ----

    def _knowledge_search(query, top_k, filters):
        """Bounded knowledge search; returns (payload, status_code).

        Query embedding uses the offline local provider when no provider is
        configured: the endpoint is read-only, so a deterministic local
        fallback keeps it usable without env setup (same policy as the CLI).
        """
        store = VectorStore(db_file=application.config['KNOWLEDGE_DB_FILE'])
        retriever = KnowledgeRetriever(store, make_indexing_provider())
        results = retriever.retrieve(query, top_k=top_k, filters=filters)
        return results, 200

    @application.get('/api/knowledge/search')
    def api_knowledge_search():
        query = request.args.get('q', '')
        top_k = request.args.get('top_k', None)
        filters = {}
        for key in request.args:
            if key in ('q', 'top_k'):
                continue
            filters[key] = request.args.get(key)
        try:
            payload, status = _knowledge_search(query, top_k, filters or None)
        except RetrievalError as exc:
            return jsonify(error='invalid_knowledge_query', message=str(exc)), 400
        except Exception:
            logger.exception('Knowledge search failed')
            return jsonify(error='knowledge_unavailable'), 503
        return jsonify(payload), status

    # -- Phase 4E-4K: advisory AI copilot (off by default; never breaks
    # alerts, investigation, or hunting; failures degrade to status payloads).

    def _require_bearer():
        """Return None when authorized, else an error response tuple."""
        expected = application.config.get('INGEST_TOKEN')
        if not expected:
            return jsonify(error='authentication_disabled'), 503
        authorization = request.headers.get('Authorization', '')
        scheme, separator, supplied = authorization.partition(' ')
        if scheme.lower() != 'bearer' or not separator or not supplied:
            return jsonify(error='authentication_required'), 401, \
                {'WWW-Authenticate': 'Bearer'}
        if not hmac.compare_digest(supplied.encode('utf-8'),
                                   expected.encode('utf-8')):
            return jsonify(error='invalid_credentials'), 401, \
                {'WWW-Authenticate': 'Bearer'}
        return None

    def _ai_engine():
        return AIInvestigationEngine(
            db_file=application.config['DB_FILE'],
            knowledge_db_file=application.config['KNOWLEDGE_DB_FILE'])

    @application.get('/api/alerts/<int:alert_id>/ai-investigation')
    def api_alert_ai_investigation(alert_id):
        try:
            result = _ai_engine().investigate(alert_id)
        except InvestigationError:
            return jsonify(error='alert_not_found'), 404
        except Exception:
            logger.exception('AI investigation failed unexpectedly')
            return jsonify(ai_schema_version=AI_SCHEMA_VERSION,
                           status='unavailable', reason='internal_error'), 503
        return jsonify(result)

    @application.post('/api/alerts/<int:alert_id>/ai-investigation')
    def api_alert_ai_investigation_recompute(alert_id):
        # LLM usage is an external effect: bearer-protected like ingestion.
        denied = _require_bearer()
        if denied is not None:
            return denied
        try:
            result = _ai_engine().investigate(alert_id)
        except InvestigationError:
            return jsonify(error='alert_not_found'), 404
        except Exception:
            logger.exception('AI investigation failed unexpectedly')
            return jsonify(ai_schema_version=AI_SCHEMA_VERSION,
                           status='unavailable', reason='internal_error'), 503
        if isinstance(result, dict) and result.get('status') == 'ok':
            # Persist (best-effort) so SOC views/validation can report on
            # completed AI investigations without inventing history.
            try:
                soc_simulation.persist_ai_result(
                    alert_id, result, db_file=application.config['DB_FILE'])
            except sqlite3.Error:
                logger.exception('AI result persistence failed (non-fatal)')
        return jsonify(result)

    @application.get('/api/alerts/<int:alert_id>/ai-report')
    def api_alert_ai_report(alert_id):
        try:
            report = _ai_engine().build_report(alert_id)
        except InvestigationError:
            return jsonify(error='alert_not_found'), 404
        except Exception:
            logger.exception('AI report failed unexpectedly')
            return jsonify(error='ai_report_unavailable'), 503
        return jsonify(report)

    @application.post('/api/hunt/ai')
    def api_hunt_ai():
        denied = _require_bearer()
        if denied is not None:
            return denied
        body = request.get_json(silent=True)
        query_text = body.get('query') if isinstance(body, dict) else None
        if not isinstance(query_text, str) or not query_text.strip():
            return jsonify(error='invalid_ai_hunt_query',
                           message='body must be {"query": "..."}'), 400
        if len(query_text) > 512:
            return jsonify(error='invalid_ai_hunt_query',
                           message='query exceeds maximum length'), 400
        try:
            outcome = execute_ai_hunt(
                query_text, db_file=application.config['DB_FILE'])
        except AIHuntError as exc:
            return jsonify(error=exc.reason, message=str(exc)), 400
        except HuntError as exc:
            return jsonify(error='invalid_hunt_query', message=str(exc)), 400
        except Exception:
            logger.exception('AI hunt failed unexpectedly')
            return jsonify(error='ai_hunt_unavailable'), 503
        return jsonify(outcome)

    # -- Phase 5: SOAR automation framework (read-only public, bearer-
    # protected writes; dry-run by default; AI cannot execute actions) --

    def _soar_engine():
        return SOAREngine(db_file=application.config['DB_FILE'])

    def _alert_row_or_none(alert_id):
        with connect(application.config['DB_FILE']) as connection:
            row = connection.execute(
                'SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
        return dict(row) if row else None

    @application.get('/api/playbooks')
    def api_playbooks():
        engine = _soar_engine()
        engine.register_built_ins()
        return jsonify({'playbooks': engine.list_playbooks()})

    @application.get('/api/playbooks/<playbook_id>')
    def api_playbook_detail(playbook_id):
        engine = _soar_engine()
        engine.register_built_ins()
        playbook = engine.get_playbook(playbook_id)
        if playbook is None:
            return jsonify(error='playbook_not_found'), 404
        return jsonify(playbook)

    @application.post('/api/playbooks/<playbook_id>/execute')
    def api_execute_playbook(playbook_id):
        # Executions are an external effect: bearer-protected.
        denied = _require_bearer()
        if denied is not None:
            return denied
        engine = _soar_engine()
        engine.register_built_ins()
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error='invalid_request',
                           message='body must be a JSON object'), 400
        alert_id = body.get('alert_id')
        if not isinstance(alert_id, int) or isinstance(alert_id, bool):
            return jsonify(error='invalid_request',
                           message='alert_id must be an integer'), 400
        dry_run = body.get('dry_run', True)
        if not isinstance(dry_run, bool):
            return jsonify(error='invalid_request',
                           message='dry_run must be a boolean'), 400
        actor = body.get('actor', 'api')
        if not isinstance(actor, str) or not USER_ACTOR_RE.match(actor):
            return jsonify(error='invalid_request',
                           message='actor must be a bounded logical username'), 400
        alert = _alert_row_or_none(alert_id)
        if alert is None:
            return jsonify(error='alert_not_found'), 404
        try:
            execution = engine.start_execution(
                playbook_id, alert, dry_run=dry_run, actor=actor)
        except PlaybookNotFoundError:
            return jsonify(error='playbook_not_found'), 404
        except SOARError as exc:
            message = str(exc)
            status = 409 if isinstance(exc, DuplicateExecution) else 400
            error = ('duplicate_execution' if isinstance(exc, DuplicateExecution)
                     else 'execution_rejected')
            payload = {'error': error, 'message': message}
            if isinstance(exc, DuplicateExecution):
                payload['existing_execution_id'] = exc.existing_execution_id
            return jsonify(payload), status
        return jsonify(execution), 202

    @application.get('/api/soar/executions')
    def api_soar_executions():
        engine = _soar_engine()
        limit = request.args.get('limit', type=int) or 50
        alert_id = request.args.get('alert_id', type=int)
        return jsonify({'executions': engine.list_executions(
            limit=limit, alert_id=alert_id)})

    @application.get('/api/soar/executions/<execution_id>')
    def api_soar_execution_detail(execution_id):
        execution = _soar_engine().get_execution(execution_id)
        if execution is None:
            return jsonify(error='execution_not_found'), 404
        return jsonify(execution)

    @application.get('/api/soar/executions/<execution_id>/audit')
    def api_soar_execution_audit(execution_id):
        engine = _soar_engine()
        if engine.get_execution(execution_id) is None:
            return jsonify(error='execution_not_found'), 404
        limit = request.args.get('limit', type=int) or 100
        return jsonify({'execution_id': execution_id,
                        'audit': engine.list_audit(execution_id, limit=limit)})

    @application.post('/api/soar/executions/<execution_id>/advance')
    def api_soar_advance_execution(execution_id):
        """Drive a dry-run execution forward until it needs external input.

        Safe by construction: advance never bypasses approval gates — it
        stops at them. Bearer-protected because it changes workflow state.
        """
        denied = _require_bearer()
        if denied is not None:
            return denied
        engine = _soar_engine()
        if engine.get_execution(execution_id) is None:
            return jsonify(error='execution_not_found'), 404
        body = request.get_json(silent=True) or {}
        actor = body.get('actor', 'analyst') if isinstance(body, dict) else 'analyst'
        if not isinstance(actor, str) or not USER_ACTOR_RE.match(actor):
            return jsonify(error='invalid_request',
                           message='actor must be a bounded logical username'), 400
        try:
            execution = engine.advance(execution_id, actor=actor)
        except SOARError as exc:
            return jsonify(error='advance_rejected', message=str(exc)), 409
        return jsonify(execution)

    @application.post('/api/soar/executions/<execution_id>/cancel')
    def api_soar_cancel_execution(execution_id):
        denied = _require_bearer()
        if denied is not None:
            return denied
        body = request.get_json(silent=True) or {}
        actor = body.get('actor', 'api') if isinstance(body, dict) else 'api'
        if not isinstance(actor, str) or not USER_ACTOR_RE.match(actor):
            return jsonify(error='invalid_request',
                           message='actor must be a bounded logical username'), 400
        reason = body.get('reason') if isinstance(body, dict) else None
        try:
            execution = _soar_engine().cancel_execution(
                execution_id, actor, reason=reason)
        except ExecutionNotFoundError:
            return jsonify(error='execution_not_found'), 404
        except SOARError as exc:
            return jsonify(error='invalid_state_transition',
                           message=str(exc)), 409
        return jsonify(execution)

    @application.get('/api/soar/approvals')
    def api_soar_approvals():
        decision = request.args.get('decision') or None
        try:
            approvals = _soar_engine().list_approvals(
                decision=decision,
                limit=request.args.get('limit', type=int) or 50)
        except SOARError as exc:
            return jsonify(error='invalid_request', message=str(exc)), 400
        return jsonify({'approvals': approvals})

    @application.post('/api/soar/approvals/<approval_id>/approve')
    def api_soar_approve(approval_id):
        denied = _require_bearer()
        if denied is not None:
            return denied
        return _decide_approval(approval_id, 'approved')

    @application.post('/api/soar/approvals/<approval_id>/reject')
    def api_soar_reject(approval_id):
        denied = _require_bearer()
        if denied is not None:
            return denied
        return _decide_approval(approval_id, 'rejected')

    def _decide_approval(approval_id, decision):
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify(error='invalid_request',
                           message='body must be a JSON object'), 400
        approver = body.get('approver')
        if not isinstance(approver, str) or not USER_ACTOR_RE.match(approver):
            return jsonify(error='invalid_request',
                           message='approver must be a bounded logical username'), 400
        try:
            execution = _soar_engine().decide_approval(
                approval_id, decision, approver,
                reason=body.get('reason'))
        except ApprovalNotFoundError:
            return jsonify(error='approval_not_found'), 404
        except ApprovalExpiredError:
            return jsonify(error='approval_expired'), 409
        except SOARError as exc:
            return jsonify(error='invalid_state_transition',
                           message=str(exc)), 409
        return jsonify(execution)

    @application.get('/api/incidents')
    def api_incidents():
        engine = _soar_engine()
        return jsonify({'incidents': engine.incident_service.list_incidents(
            limit=request.args.get('limit', type=int) or 50)})

    @application.get('/api/incidents/<incident_id>')
    def api_incident_detail(incident_id):
        incident = _soar_engine().incident_service.get_incident(incident_id)
        if incident is None:
            return jsonify(error='incident_not_found'), 404
        return jsonify(incident)

    @application.get('/api/alerts/<int:alert_id>/investigation')
    def api_alert_investigation(alert_id):
        service = InvestigationService(db_file=application.config['DB_FILE'])
        try:
            package = service.build_investigation(alert_id)
        except InvestigationError:
            return jsonify(error='alert_not_found'), 404
        with_knowledge = (request.args.get('with_knowledge', '').strip().lower()
                          in ('1', 'true', 'yes', 'on'))
        if with_knowledge:
            try:
                query = ' '.join([
                    package['alert'].get('rule') or '',
                    package['alert'].get('details') or '',
                ]).strip()[:512]
                payload, _status = _knowledge_search(query, 5, None)
                package['knowledge_context'] = {
                    'status': 'ok',
                    'query': payload['query'],
                    'retrieved_documents': payload['results'],
                }
            except Exception:
                # Advisory context must never break the investigation package.
                logger.exception('Knowledge context retrieval failed')
                package['knowledge_context'] = {'status': 'unavailable',
                                                'reason': 'retrieval_error'}
        # Advisory AI perspective (disabled by default; never networked here).
        apply_investigation_provider(
            package, make_investigation_provider())
        return jsonify(package)

    # -- SOC operations integration: analyst console, simulation lab, and
    # deterministic validation. Read-only endpoints stay public like the rest
    # of the dashboard; anything with external effects stays bearer-protected.

    def _soc_intel_rows(alert_id):
        with connect(application.config['DB_FILE']) as connection:
            return [dict(row) for row in connection.execute(
                'SELECT key, value FROM alert_enrichment WHERE alert_id = ?',
                (alert_id,))]

    @application.get('/api/soc/overview')
    def api_soc_overview():
        db_file = application.config['DB_FILE']
        with connect(db_file) as connection:
            severity_rows = connection.execute(
                'SELECT severity, COUNT(*) FROM alerts GROUP BY severity').fetchall()
            total = connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
            active_investigations = connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE investigation_status IN "
                "('new', 'investigating')").fetchone()[0]
            open_incidents = connection.execute(
                "SELECT COUNT(*) FROM soar_incidents WHERE status = 'open'").fetchone()[0]
            pending_approvals = connection.execute(
                "SELECT COUNT(*) FROM soar_approvals WHERE decision = 'pending'").fetchone()[0]
            running_executions = connection.execute(
                "SELECT COUNT(*) FROM soar_executions WHERE state IN "
                "('PENDING', 'VALIDATING', 'WAITING_APPROVAL', 'APPROVED', 'RUNNING')").fetchone()[0]
            ai_investigations = connection.execute(
                "SELECT COUNT(*) FROM ai_investigation_results WHERE status = 'ok'").fetchone()[0]
            detection_events = connection.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        try:
            ai_provider = make_llm_provider(os.environ).describe()
        except Exception:
            ai_provider = {'provider': 'unknown', 'model': None}
        by_severity = {row[0]: row[1] for row in severity_rows}
        return jsonify({
            'total_alerts': total,
            'critical_alerts': by_severity.get('CRITICAL', 0),
            'high_alerts': by_severity.get('HIGH', 0),
            'medium_alerts': by_severity.get('MEDIUM', 0),
            'low_alerts': by_severity.get('LOW', 0),
            'active_investigations': active_investigations,
            'open_incidents': open_incidents,
            'pending_approvals': pending_approvals,
            'running_executions': running_executions,
            'ai_investigations': ai_investigations,
            'ai_provider': ai_provider.get('provider'),
            'ai_model': ai_provider.get('model'),
            'detection_events': detection_events,
        })

    @application.get('/api/soc/alerts')
    def api_soc_alerts():
        # The existing public /api/alerts payload already carries rule,
        # severity, risk, Jev, correlation, and investigation status; add the
        # per-alert incident + AI links the alert queue shows.
        alerts = get_alerts_with_hostnames(db_file=application.config['DB_FILE'])
        incident_by_alert = {}
        ai_alert_ids = set()
        with connect(application.config['DB_FILE']) as connection:
            for row in connection.execute('SELECT alert_ids_json FROM soar_incidents'):
                try:
                    alert_ids = json.loads(row['alert_ids_json'] or '[]')
                except (TypeError, ValueError):
                    continue
                for alert_id in alert_ids:
                    incident_by_alert.setdefault(alert_id, []).append(row['alert_ids_json'])
            for row in connection.execute('SELECT alert_id FROM ai_investigation_results'):
                ai_alert_ids.add(row['alert_id'])
        for alert in alerts:
            alert['incident_ids'] = incident_by_alert.get(alert['id'], [])
            alert['ai_status'] = ('ok' if alert['id'] in ai_alert_ids
                                  else alert.get('ai_status'))
        return jsonify(alerts)

    @application.get('/api/soc/alerts/<int:alert_id>')
    def api_soc_alert_detail(alert_id):
        db_file = application.config['DB_FILE']
        with connect(db_file) as connection:
            row = connection.execute(
                'SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
        if row is None:
            return jsonify(error='alert_not_found'), 404
        alert = {'id': row['id'], 'time': row['time'], 'rule': row['rule'],
                 'severity': row['severity'], 'details': row['details']}
        alert.update(_soc_alert_fields(row))
        alert.update(_alert_entity_fields(alert))
        alert['hostnames'] = _alert_hostnames(alert, db_file=db_file)
        incident_ids = []
        with connect(application.config['DB_FILE']) as connection:
            for incident_row in connection.execute(
                    'SELECT incident_id, alert_ids_json FROM soar_incidents'):
                try:
                    if alert_id in json.loads(incident_row['alert_ids_json'] or '[]'):
                        incident_ids.append(incident_row['incident_id'])
                except (TypeError, ValueError):
                    continue
        alert['incident_ids'] = incident_ids
        alert['intel'] = _soc_intel_rows(alert_id)
        return jsonify(alert)

    @application.get('/api/soc/alerts/<int:alert_id>/full')
    def api_soc_alert_full(alert_id):
        db_file = application.config['DB_FILE']
        with connect(db_file) as connection:
            row = connection.execute(
                'SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
        if row is None:
            return jsonify(error='alert_not_found'), 404
        alert = {'id': row['id'], 'time': row['time'], 'rule': row['rule'],
                 'severity': row['severity'], 'details': row['details']}
        alert.update(_soc_alert_fields(row))
        alert.update(_alert_entity_fields(alert))
        alert['hostnames'] = _alert_hostnames(alert, db_file=db_file)
        # Stored enrichment rows (threat-intel decisions, source IP) so the
        # analyst sees the same enrichment the pipeline used.
        alert['intel'] = _soc_intel_rows(alert_id)
        # Adapters are built lazily; keep handler-level failures advisory.
        try:
            service = InvestigationService(db_file=db_file)
            investigation = service.build_investigation(alert_id)
        except InvestigationError:
            return jsonify(error='alert_not_found'), 404
        except Exception:
            logger.exception('Investigation build failed')
            investigation = None
        try:
            ai_result = _ai_engine().investigate(alert_id)
        except Exception:
            logger.exception('AI status lookup failed')
            ai_result = {'status': 'unavailable', 'reason': 'internal_error'}
        return jsonify({
            'alert': alert,
            'investigation': investigation,
            'ai': ai_result,
            'soar': _soc_soar_bundle(alert_id, alert),
        })

    def _soc_soar_bundle(alert_id, alert):
        """Playbook matches, executions, approvals, and audit for one alert.

        Shared by /full and the lightweight /soar poll so the console can
        keep an open alert detail current without re-running the AI engine.
        """
        db_file = application.config['DB_FILE']
        engine = _soar_engine()
        executions = engine.list_executions(alert_id=alert_id, limit=10)
        executions = [engine.get_execution(execution['execution_id']) or execution
                      for execution in executions]
        approval_rows = []
        for execution in executions:
            approval_rows.extend(engine.list_approvals(limit=100))
        approval_rows = [approval for approval in approval_rows
                         if approval.get('execution_id') in
                         {execution['execution_id'] for execution in executions}]
        playbook_matches = []
        matched_playbook = None
        engine.register_built_ins()
        intel_match = _alert_has_intel(alert_id, db_file=db_file)
        for playbook in engine.list_playbooks():
            if playbook.get('enabled') and playbook_matches_alert(
                    playbook.get('definition', {}), alert,
                    intel_match=intel_match):
                playbook_matches.append(playbook['playbook_id'])
                if matched_playbook is None:
                    matched_playbook = playbook
        recommendation = None
        if matched_playbook is not None:
            try:
                recommendation = engine.recommend_execution(
                    matched_playbook['playbook_id'], alert,
                    {'recommended_action': 'run playbook in dry-run',
                     'source': 'soc-console'})
            except SOARError:
                recommendation = None
        audit_rows = []
        for execution in executions:
            try:
                audit_rows.extend(engine.list_audit(execution['execution_id'], limit=100))
            except SOARError:
                continue
        return {
            'matched_playbooks': playbook_matches,
            'playbook': matched_playbook,
            'recommendation': recommendation,
            'executions': executions,
            'approvals': approval_rows,
            'audit': audit_rows,
        }

    @application.get('/api/soc/alerts/<int:alert_id>/soar')
    def api_soc_alert_soar(alert_id):
        """Lightweight SOAR/approval/audit state for one alert.

        Lets the console keep an open alert detail live (executions,
        approvals, audit) without re-running the AI investigation.
        """
        db_file = application.config['DB_FILE']
        with connect(db_file) as connection:
            row = connection.execute(
                'SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
        if row is None:
            return jsonify(error='alert_not_found'), 404
        alert = {'id': row['id'], 'time': row['time'], 'rule': row['rule'],
                 'severity': row['severity'], 'details': row['details']}
        alert.update(_soc_alert_fields(row))
        return jsonify({
            'alert': alert,
            'investigation_status': alert.get('investigation_status'),
            'soar': _soc_soar_bundle(alert_id, alert),
        })

    @application.post('/api/simulation/scenarios/<scenario_id>/generate')
    def api_simulation_generate(scenario_id):
        denied = _require_bearer()
        if denied is not None:
            return denied
        try:
            run = soc_simulation.create_run(
                scenario_id, db_file=application.config['DB_FILE'])
        except soc_simulation.SimulationError as exc:
            return jsonify(error='invalid_scenario', message=str(exc)), 400
        except sqlite3.Error:
            logger.exception('Simulation run creation failed')
            return jsonify(error='storage_unavailable'), 503
        return jsonify(run), 201

    @application.post('/api/simulation/scenarios/<scenario_id>/process')
    def api_simulation_process(scenario_id):
        denied = _require_bearer()
        if denied is not None:
            return denied
        body = request.get_json(silent=True) or {}
        run_id = body.get('run_id') if isinstance(body, dict) else None
        if not isinstance(run_id, str) or not run_id.strip() or len(run_id) > 64:
            return jsonify(error='invalid_request',
                           message='run_id is required'), 400
        try:
            run = soc_simulation.get_run(run_id, db_file=application.config['DB_FILE'])
        except soc_simulation.SimulationError:
            return jsonify(error='run_not_found'), 404
        if run['scenario_id'] != scenario_id:
            return jsonify(error='run_scenario_mismatch'), 400
        try:
            run = soc_simulation.process_run(
                run_id, db_file=application.config['DB_FILE'])
            validation = soc_simulation.validate_run(
                run_id, db_file=application.config['DB_FILE'])
            soc_simulation.store_validation(
                run_id, validation, db_file=application.config['DB_FILE'])
        except soc_simulation.SimulationError as exc:
            return jsonify(error='simulation_error', message=str(exc)), 400
        except sqlite3.Error:
            logger.exception('Simulation processing failed')
            return jsonify(error='storage_unavailable'), 503
        return jsonify({'run': run, 'validation': validation})

    @application.get('/api/simulation/runs/<run_id>')
    def api_simulation_run(run_id):
        try:
            run = soc_simulation.get_run(run_id, db_file=application.config['DB_FILE'])
        except soc_simulation.SimulationError:
            return jsonify(error='run_not_found'), 404
        return jsonify(run)

    @application.get('/api/simulation/runs/<run_id>/validation')
    def api_simulation_validation(run_id):
        try:
            run = soc_simulation.get_run(run_id, db_file=application.config['DB_FILE'])
        except soc_simulation.SimulationError:
            return jsonify(error='run_not_found'), 404
        validation = run.get('validation')
        if validation is None:
            try:
                validation = soc_simulation.validate_run(
                    run_id, db_file=application.config['DB_FILE'])
            except soc_simulation.SimulationError as exc:
                return jsonify(error='simulation_error', message=str(exc)), 400
        return jsonify(validation)

    @application.get('/api/simulation/scenarios')
    def api_simulation_scenarios():
        return jsonify({'scenarios': soc_simulation.scenario_catalog()})

    @application.get('/api/rules')
    def api_rules():
        """Detection rule registry: thresholds for the 'why did this fire' view."""
        registry = load_rules()
        return jsonify({'rules': [
            {'rule_id': rule.rule_id, 'name': rule.name, 'code': rule.code,
             'description': rule.description, 'severity': rule.severity,
             'threshold': rule.threshold, 'window_seconds': rule.window_seconds,
             'event_types': list(rule.event_types), 'mitre': list(rule.mitre),
             'enabled': rule.enabled}
            for rule in registry.all()
        ]})

    @application.get('/api/events/recent')
    def api_events_recent():
        """Bounded recent-event feed for the dashboard live stream."""
        limit = request.args.get('limit', type=int) or 50
        limit = max(1, min(limit, 200))
        with connect(application.config['DB_FILE']) as connection:
            rows = connection.execute(
                'SELECT event_id, event_time, ingestion_time, event_type, '
                'src_ip, dst_ip, dst_port, host, user_name, action, outcome, source '
                'FROM events ORDER BY ingestion_time DESC, event_id LIMIT ?',
                (limit,)).fetchall()
        return jsonify({'events': [dict(row) for row in rows]})

    @application.get('/api/simulation/runs/<run_id>/events')
    def api_simulation_run_events(run_id):
        """Events + alert IDs for one simulation run (run-pipeline visualization)."""
        try:
            run = soc_simulation.get_run(
                run_id, db_file=application.config['DB_FILE'])
        except soc_simulation.SimulationError:
            return jsonify(error='run_not_found'), 404
        with connect(application.config['DB_FILE']) as connection:
            events = []
            for event_id in run['event_ids']:
                row = connection.execute(
                    'SELECT event_id, event_time, event_type, src_ip, dst_ip, '
                    'dst_port, host, user_name, action, outcome FROM events '
                    'WHERE event_id = ?', (event_id,)).fetchone()
                if row is not None:
                    events.append(dict(row))
            alerts = []
            for alert_id in run['alert_ids']:
                row = connection.execute(
                    'SELECT id, rule_id, severity, deterministic_risk_score, '
                    'jev_priority, jev_investigation_required, '
                    'source_event_ids_json, mitre_techniques_json FROM alerts '
                    'WHERE id = ?', (alert_id,)).fetchone()
                if row is None:
                    continue
                alert = dict(row)
                try:
                    alert['mitre'] = json.loads(alert.pop('mitre_techniques_json')
                                                or '[]')
                except (TypeError, ValueError):
                    alert['mitre'] = []
                try:
                    alert['source_event_ids'] = json.loads(
                        alert.pop('source_event_ids_json') or '[]')
                except (TypeError, ValueError):
                    alert['source_event_ids'] = []
                alerts.append(alert)
        return jsonify({'run_id': run_id, 'scenario_id': run['scenario_id'],
                        'status': run['status'], 'events': events,
                        'alerts': alerts})

    @application.post('/api/simulation/reset')
    def api_simulation_reset():
        """Reset ONLY synthetic simulation-lab data (same scope as the CLI tool)."""
        denied = _require_bearer()
        if denied is not None:
            return denied
        try:
            result = soc_simulation.delete_simulation_data(
                db_file=application.config['DB_FILE'])
        except sqlite3.Error:
            logger.exception('Simulation reset failed')
            return jsonify(error='storage_unavailable'), 503
        return jsonify(result)

    @application.post('/api/simulation/validate-all')
    def api_simulation_validate_all():
        """Run every scenario end-to-end and return deterministic validation.

        Executes generate + process + validate + store for all catalogued
        scenarios in sequence (AI is never invoked here; the AI check is
        advisory and reports from persisted results only). Each scenario runs
        with clean rate/suppression state so results match a cold start.
        """
        denied = _require_bearer()
        if denied is not None:
            return denied
        db_file = application.config['DB_FILE']
        results = []
        try:
            for scenario in soc_simulation.scenario_catalog():
                _clear_pipeline_state(db_file)
                run = soc_simulation.create_run(
                    scenario['scenario_id'], db_file=db_file)
                run = soc_simulation.process_run(run['run_id'], db_file=db_file)
                validation = soc_simulation.validate_run(
                    run['run_id'], db_file=db_file)
                soc_simulation.store_validation(
                    run['run_id'], validation, db_file=db_file)
                results.append({
                    'run_id': run['run_id'],
                    'scenario_id': scenario['scenario_id'],
                    'name': scenario['name'],
                    'classification': scenario['classification'],
                    'expected': validation['expected'],
                    'outcome': validation['outcome'],
                    'false_positive': validation.get('false_positive', False),
                    'failed_checks': validation['failed_checks'],
                    'checks': validation['checks'],
                    'event_count': run['event_count'],
                    'actual': validation['actual'],
                })
        except soc_simulation.SimulationError as exc:
            return jsonify(error='simulation_error', message=str(exc)), 400
        except sqlite3.Error:
            logger.exception('Full validation failed')
            return jsonify(error='storage_unavailable'), 503
        totals = {'scenarios': len(results), 'passed': 0, 'warning': 0, 'failed': 0}
        for result in results:
            totals[result['outcome']] = totals.get(result['outcome'], 0) + 1
        return jsonify({'totals': totals, 'results': results,
                        'generated_at': utc_now()})

    @application.post('/api/simulation/demo')
    def api_simulation_demo():
        """Guided demo: benign pass, attack, pipeline, AI, incident, SOAR, audit.

        Uses the real simulation lab and the real pipeline only; AI runs when a
        provider is configured (mock counts); SOAR always executes dry-run.
        Returns the step list plus created identifiers for the dashboard.
        """
        denied = _require_bearer()
        if denied is not None:
            return denied
        db_file = application.config['DB_FILE']
        steps = []

        def _step(number, name, detail):
            steps.append({'step': number, 'name': name, 'detail': detail})

        try:
            # 1-2: benign pass (honest baseline: the rules stay silent).
            _clear_pipeline_state(db_file)
            benign = soc_simulation.create_run('benign_auth', db_file=db_file)
            benign = soc_simulation.process_run(benign['run_id'], db_file=db_file)
            benign_validation = soc_simulation.validate_run(
                benign['run_id'], db_file=db_file)
            soc_simulation.store_validation(
                benign['run_id'], benign_validation, db_file=db_file)
            _step(1, 'benign_baseline',
                  f"benign_auth: {benign['event_count']} events processed, "
                  f"{len(benign['alert_ids'])} alerts (expected 0) — outcome "
                  f"{benign_validation['outcome']}")
            _step(2, 'detection_baseline',
                  'deterministic rules stayed silent on benign telemetry'
                  if not benign['alert_ids'] else
                  'unexpected alerts on benign telemetry — see validation')

            # 3-5: brute force through detection, correlation, risk, Jev.
            _clear_pipeline_state(db_file)
            attack = soc_simulation.create_run('brute_force', db_file=db_file)
            attack = soc_simulation.process_run(attack['run_id'], db_file=db_file)
            attack_validation = soc_simulation.validate_run(
                attack['run_id'], db_file=db_file)
            soc_simulation.store_validation(
                attack['run_id'], attack_validation, db_file=db_file)
            alert_ids = attack['alert_ids']
            _step(3, 'attack_ingested',
                  f"brute_force: {attack['event_count']} synthetic auth events "
                  f"ingested and normalized")
            _step(4, 'detection_fired',
                  '; '.join(f"{a['rule_id']} severity {a['severity']} risk "
                            f"{a['risk_score']}" for a in
                            attack_validation['actual']['alerts'])
                  or 'no alert (unexpected)')
            _step(5, 'jev_decision',
                  'Jev advisory attached to each alert (deterministic fallback '
                  'unless JEV_ENABLED=1)')

            # 6: AI investigation (mock counts; disabled stays honest).
            ai_status = 'disabled'
            for alert_id in alert_ids:
                try:
                    ai_result = _ai_engine().investigate(alert_id)
                except Exception:
                    logger.exception('Demo AI investigation failed')
                    ai_result = {'status': 'unavailable'}
                if ai_result.get('status') == 'ok':
                    soc_simulation.persist_ai_result(
                        alert_id, ai_result, db_file=db_file)
                    ai_status = 'ok'
                elif ai_status != 'ok':
                    ai_status = ai_result.get('status', 'unavailable')
            _step(6, 'ai_investigation',
                  f"AI analyst status: {ai_status} — advisory only, "
                  "deterministic detection unaffected")

            # 7-10: incident, SOAR dry-run, approval gate, audit.
            incident_id = None
            execution_id = None
            approval_id = None
            if alert_ids:
                primary_alert = _alert_row_or_none(alert_ids[0])
                if primary_alert is not None:
                    created = _soar_engine().incident_service.create_incident(
                        f"Demo brute force — alert {alert_ids[0]}",
                        severity=str(primary_alert['severity'] or 'medium').lower(),
                        alert_id=alert_ids[0],
                        correlation_id=primary_alert['correlation_id'])
                    incident_id = created['incident_id']
                engine = _soar_engine()
                engine.register_built_ins()
                playbook_id = None
                for playbook in engine.list_playbooks():
                    if playbook.get('enabled') and playbook_matches_alert(
                            playbook.get('definition', {}),
                            _alert_row_or_none(alert_ids[0]),
                            intel_match=_alert_has_intel(alert_ids[0],
                                                         db_file=db_file)):
                        playbook_id = playbook['playbook_id']
                        break
                if playbook_id and primary_alert is not None:
                    try:
                        execution = engine.start_execution(
                            playbook_id, primary_alert, dry_run=True,
                            actor='demo')
                        execution_id = execution['execution_id']
                        # Drive to the approval gate (advance never bypasses it).
                        execution = engine.advance(execution_id, actor='demo')
                        for approval in engine.list_approvals(limit=100):
                            if (approval.get('execution_id') == execution_id
                                    and approval.get('decision') == 'pending'):
                                approval_id = approval['approval_id']
                                break
                    except SOARError as exc:
                        logger.warning('Demo SOAR execution skipped: %s', exc)
            _step(7, 'incident_created', incident_id or 'no incident (no alert)')
            _step(8, 'soar_playbook_selected',
                  f"execution {execution_id} (dry-run)" if execution_id
                  else 'no playbook matched')
            _step(9, 'approval_gate',
                  f"approval {approval_id} pending — human decision required"
                  if approval_id else 'no gated action in this playbook')
            _step(10, 'audit_complete',
                  'every step recorded in the SOAR/investigation audit trail')
        except soc_simulation.SimulationError as exc:
            return jsonify(error='simulation_error', message=str(exc)), 400
        except sqlite3.Error:
            logger.exception('Demo run failed')
            return jsonify(error='storage_unavailable'), 503
        return jsonify({'steps': steps, 'alert_ids': alert_ids,
                        'incident_id': incident_id,
                        'execution_id': execution_id,
                        'approval_id': approval_id,
                        'ai_status': ai_status,
                        'run_id': attack['run_id'],
                        'benign_run_id': benign['run_id']})

    @application.post('/api/alerts/<int:alert_id>/incident')
    def api_create_alert_incident(alert_id):
        """Promote one alert into a deduplicated SOAR incident."""
        denied = _require_bearer()
        if denied is not None:
            return denied
        alert = _alert_row_or_none(alert_id)
        if alert is None:
            return jsonify(error='alert_not_found'), 404
        body = request.get_json(silent=True) or {}
        actor = body.get('actor', 'analyst') if isinstance(body, dict) else 'analyst'
        if not isinstance(actor, str) or not USER_ACTOR_RE.match(actor):
            return jsonify(error='invalid_request',
                           message='actor must be a bounded logical username'), 400
        severity = str(alert['severity'] or 'medium').lower()
        if severity not in ('low', 'medium', 'high', 'critical'):
            severity = 'medium'
        try:
            created = _soar_engine().incident_service.create_incident(
                f"Alert {alert_id} — {alert['rule']}", severity=severity,
                alert_id=alert_id, correlation_id=alert['correlation_id'])
        except SOARError as exc:
            return jsonify(error='incident_rejected', message=str(exc)), 400
        return jsonify(created), 201

    @application.get('/api/simulation/summary')
    def api_simulation_summary():
        return jsonify(soc_simulation.scenario_summary(
            db_file=application.config['DB_FILE']))

    @application.post('/api/alerts/<int:alert_id>/ai-question')
    def api_alert_ai_question(alert_id):
        denied = _require_bearer()
        if denied is not None:
            return denied
        body = request.get_json(silent=True)
        question = body.get('question') if isinstance(body, dict) else None
        if not isinstance(question, str) or not question.strip():
            return jsonify(error='invalid_request',
                           message='question is required'), 400
        question = question.strip()
        if len(question) > 256:
            return jsonify(error='invalid_request',
                           message='question exceeds 256 characters'), 400
        db_file = application.config['DB_FILE']
        with connect(db_file) as connection:
            row = connection.execute(
                'SELECT id FROM alerts WHERE id = ?', (alert_id,)).fetchone()
        if row is None:
            return jsonify(error='alert_not_found'), 404
        answer = _answer_alert_question(
            question, alert_id, db_file=application.config['DB_FILE'])
        return jsonify(answer)

    @application.get('/api/incidents/<incident_id>/detail')
    def api_incident_full_detail(incident_id):
        engine = _soar_engine()
        incident = engine.incident_service.get_incident(incident_id)
        if incident is None:
            return jsonify(error='incident_not_found'), 404
        executions = []
        audit_rows = []
        with connect(application.config['DB_FILE']) as connection:
            alert_ids = incident.get('alert_ids') or []
            for alert_id in alert_ids:
                for execution in engine.list_executions(alert_id=alert_id, limit=10):
                    executions.append(
                        engine.get_execution(execution['execution_id']) or execution)
        for execution in executions:
            try:
                audit_rows.extend(
                    engine.list_audit(execution['execution_id'], limit=100))
            except SOARError:
                continue
        investigations = []
        for alert_id in incident.get('alert_ids') or []:
            try:
                investigations.append(
                    InvestigationService(
                        db_file=application.config['DB_FILE']
                    ).build_investigation(alert_id))
            except Exception:
                continue
        return jsonify({
            'incident': incident,
            'executions': executions,
            'approvals': engine.list_approvals(limit=100),
            'audit': audit_rows,
            'investigations': investigations,
        })

    @application.post('/api/ingest')
    def api_ingest():
        limiter = application.extensions['ingest_rate_limiter']
        if not limiter.allow(request.remote_addr or 'unknown'):
            return jsonify(error='rate_limit_exceeded'), 429, {'Retry-After': '60'}
        expected = application.config.get('INGEST_TOKEN')
        if not expected:
            return jsonify(error='ingestion_disabled'), 503
        authorization = request.headers.get('Authorization', '')
        scheme, separator, supplied = authorization.partition(' ')
        if scheme.lower() != 'bearer' or not separator or not supplied:
            return jsonify(error='authentication_required'), 401, {'WWW-Authenticate': 'Bearer'}
        if not hmac.compare_digest(supplied.encode('utf-8'), expected.encode('utf-8')):
            return jsonify(error='invalid_credentials'), 401, {'WWW-Authenticate': 'Bearer'}
        if not request.is_json:
            return jsonify(error='application_json_required'), 415
        try:
            payload = request.get_json(silent=False)
            if isinstance(payload, dict) and 'event_id' not in payload:
                return jsonify(error='event_id_required'), 400
            event = SecurityEvent.from_payload(payload, default_source='api')
        except EventValidationError as exc:
            return jsonify(error='invalid_event', message=str(exc)), 400
        try:
            accepted = process_event(event, db_file=application.config['DB_FILE'])
        except EventIdConflictError:
            return jsonify(error='event_id_conflict'), 409
        except sqlite3.Error:
            logger.exception('Event ingestion failed due to a storage error')
            return jsonify(error='storage_unavailable'), 503
        status = 202 if accepted else 200
        return jsonify(event_id=event.event_id, duplicate=not accepted), status

    return application


app = create_app()


if __name__ == '__main__':
    from waitress import serve

    port = int(os.environ.get('PORT', '5000'))
    if not 1 <= port <= 65535:
        raise ValueError('PORT must be between 1 and 65535')
    serve(app, host='127.0.0.1', port=port)
