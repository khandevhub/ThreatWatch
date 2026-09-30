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

from database import DB, EventIdConflictError, connect, init_db
from detector import process_event
from event_model import EventValidationError, SecurityEvent

from security_config import load_ingest_token, validate_ingest_token

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


INVESTIGATION_STATUSES = ('new', 'in_progress', 'closed')


def set_investigation_status(alert_id, status, db_file=None):
    if status not in INVESTIGATION_STATUSES:
        raise ValueError('invalid investigation status')
    with connect(db_file or DB) as connection:
        cursor = connection.execute(
            'UPDATE alerts SET investigation_status = ? WHERE id = ?',
            (status, alert_id),
        )
        connection.commit()
        return cursor.rowcount == 1


def create_app(config=None):
    application = Flask(__name__)
    application.config.update(
        DB_FILE=DB,
        INGEST_TOKEN=load_ingest_token(),
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
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
        if not isinstance(body, dict) or body.get('status') not in INVESTIGATION_STATUSES:
            return jsonify(error='invalid_status'), 400
        try:
            updated = set_investigation_status(
                alert_id, body['status'], db_file=application.config['DB_FILE'])
        except sqlite3.Error:
            logger.exception('Investigation status update failed')
            return jsonify(error='storage_unavailable'), 503
        if not updated:
            return jsonify(error='alert_not_found'), 404
        return jsonify(alert_id=alert_id, status=body['status'])

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
