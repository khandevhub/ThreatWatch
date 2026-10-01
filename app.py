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
from retrieval import KnowledgeRetriever, RetrievalError
from vector_store import KNOWLEDGE_DB_DEFAULT, VectorStore

from security_config import load_ingest_token, validate_ingest_token
from soar import (ApprovalExpiredError, ApprovalNotFoundError,
                  DuplicateExecution, ExecutionNotFoundError,
                  PlaybookNotFoundError, SOAREngine, SOARError,
                  USER_ACTOR_RE)

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
        alerts.append(alert)
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
