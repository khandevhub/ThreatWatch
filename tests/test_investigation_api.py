"""Phase 3I: investigation, timeline, hunt, and status API endpoints."""
import sqlite3

import pytest

import detector
from detector import process_event


TOKEN = 'phase3-api-test-' + 'x' * 48
AUTH = {'Authorization': 'Bearer ' + TOKEN}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    dbfile = tmp_path / 'api3.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    detector.DB = str(dbfile)
    detector.reload_soc_components({})
    detector.init_db(str(dbfile))
    from app import create_app
    application = create_app({
        'DB_FILE': str(dbfile), 'INGEST_TOKEN': TOKEN, 'TESTING': True,
    })
    # One realistic spray alert to investigate.
    for user in ('alice', 'bob', 'carol'):
        process_event({'event_id': f'api3-{user}', 'type': 'auth_failed',
                       'src': '203.0.113.7', 'user': user})
    with sqlite3.connect(str(dbfile)) as connection:
        alert_id = connection.execute(
            'SELECT id FROM alerts ORDER BY id DESC LIMIT 1').fetchone()[0]
    with application.test_client() as test_client:
        yield test_client, str(dbfile), alert_id


def _latest_alert_id(dbfile):
    with sqlite3.connect(dbfile) as connection:
        return connection.execute(
            'SELECT id FROM alerts ORDER BY id DESC LIMIT 1').fetchone()[0]


# -- GET /api/alerts/<id>/investigation ---------------------------------------

def test_investigation_endpoint_returns_package(client):
    http, _, alert_id = client
    response = http.get(f'/api/alerts/{alert_id}/investigation')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    package = response.get_json()
    for section in ('alert', 'risk', 'evidence', 'timeline', 'indicators',
                    'threat_intel', 'mitre', 'related_alerts',
                    'investigation_questions'):
        assert section in package, section
    assert package['alert']['alert_id'] == alert_id
    # The advisory AI layer is disabled by default and never calls out.
    assert package['ai_perspective']['status'] == 'disabled'


def test_investigation_endpoint_enables_mock_provider_via_env(client, monkeypatch):
    http, _, alert_id = client
    monkeypatch.setenv('INVESTIGATION_AI_ENABLED', '1')
    package = http.get(f'/api/alerts/{alert_id}/investigation').get_json()
    assert package['ai_perspective']['status'] == 'ok'
    assert package['ai_perspective']['provider'] == 'mock'
    assert package['ai_perspective']['advisory_only'] is True


def test_investigation_endpoint_404_for_unknown_alert(client):
    http, _, _ = client
    response = http.get('/api/alerts/999999/investigation')
    assert response.status_code == 404
    assert response.get_json()['error'] == 'alert_not_found'


# -- GET /api/alerts/<id>/timeline ---------------------------------------------

def test_timeline_endpoint_returns_ordered_events(client):
    http, _, alert_id = client
    response = http.get(f'/api/alerts/{alert_id}/timeline')
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['alert_id'] == alert_id
    assert payload['timeline']['total_events'] >= 3
    timestamps = [entry['timestamp'] for entry in payload['timeline']['entries']]
    assert timestamps == sorted(timestamps, key=lambda value: (value is None, value))


def test_timeline_endpoint_404_for_unknown_alert(client):
    http, _, _ = client
    assert http.get('/api/alerts/999999/timeline').status_code == 404


# -- GET /api/hunt ---------------------------------------------------------------

def test_hunt_endpoint_runs_filters(client):
    http, _, _ = client
    response = http.get('/api/hunt?src_ip=203.0.113.7&user=alice')
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['total'] >= 1
    assert all(row['src_ip'] == '203.0.113.7' for row in payload['results'])


def test_hunt_endpoint_pagination_and_limits(client):
    http, _, _ = client
    payload = http.get('/api/hunt?limit=1&offset=0').get_json()
    assert len(payload['results']) == 1
    assert payload['limit'] == 1
    assert http.get('/api/hunt?limit=0').status_code == 400
    assert http.get('/api/hunt?limit=501').status_code == 400
    assert http.get('/api/hunt?offset=-1').status_code == 400


def test_hunt_endpoint_rejects_bad_queries_as_400(client):
    http, _, _ = client
    response = http.get('/api/hunt?src_ip=not-an-ip')
    assert response.status_code == 400
    assert response.get_json()['error'] == 'invalid_hunt_query'
    response = http.get('/api/hunt?not_a_filter=1')
    assert response.status_code == 400
    response = http.get('/api/hunt?user=bob%27%3B%20DROP%20TABLE%20events%3B%20--')
    assert response.status_code == 400
    # The events table is intact after the rejected queries.
    assert http.get('/api/hunt?limit=1').status_code == 200


def test_hunt_endpoint_unknown_filters_match_nothing(client):
    http, _, _ = client
    payload = http.get('/api/hunt?src_ip=203.0.113.99').get_json()
    assert payload['total'] == 0 and payload['results'] == []


# -- POST /api/alerts/<id>/status -------------------------------------------------

def test_status_endpoint_requires_authentication(client):
    http, _, alert_id = client
    response = http.post(f'/api/alerts/{alert_id}/status', json={'status': 'investigating'})
    assert response.status_code == 401
    bad_token = dict(AUTH, Authorization='Bearer wrong-token')
    assert http.post(f'/api/alerts/{alert_id}/status',
                     json={'status': 'investigating'},
                     headers=bad_token).status_code == 401


def test_status_endpoint_rejects_invalid_body(client):
    http, _, alert_id = client
    assert http.post(f'/api/alerts/{alert_id}/status', headers=AUTH).status_code == 400
    assert http.post(f'/api/alerts/{alert_id}/status',
                     json={'status': 'warp'}, headers=AUTH).status_code == 400
    assert http.post(f'/api/alerts/{alert_id}/status', data='not-json{',
                     content_type='application/json',
                     headers=AUTH).status_code == 400


def test_status_endpoint_validates_transitions(client):
    http, dbfile, alert_id = client
    ok = http.post(f'/api/alerts/{alert_id}/status',
                   json={'status': 'investigating'}, headers=AUTH)
    assert ok.status_code == 200
    assert ok.get_json() == {'alert_id': alert_id, 'status': 'investigating'}
    with sqlite3.connect(dbfile) as connection:
        status = connection.execute(
            'SELECT investigation_status FROM alerts WHERE id = ?',
            (alert_id,)).fetchone()[0]
    assert status == 'investigating'


def test_status_endpoint_returns_409_for_invalid_transitions(client):
    http, dbfile, alert_id = client
    dismissed = http.post(f'/api/alerts/{alert_id}/status',
                          json={'status': 'dismissed'}, headers=AUTH)
    assert dismissed.status_code == 200
    blocked = http.post(f'/api/alerts/{alert_id}/status',
                        json={'status': 'resolved'}, headers=AUTH)
    assert blocked.status_code == 409
    assert blocked.get_json()['error'] == 'invalid_transition'
    with sqlite3.connect(dbfile) as connection:
        status = connection.execute(
            'SELECT investigation_status FROM alerts WHERE id = ?',
            (alert_id,)).fetchone()[0]
    assert status == 'dismissed'


def test_status_endpoint_404_for_unknown_alert(client):
    http, _, _ = client
    response = http.post('/api/alerts/999999/status',
                         json={'status': 'investigating'}, headers=AUTH)
    assert response.status_code == 404
    assert response.get_json()['error'] == 'alert_not_found'


def test_status_endpoint_audits_transitions(client):
    http, dbfile, alert_id = client
    http.post(f'/api/alerts/{alert_id}/status',
              json={'status': 'in_progress'}, headers=AUTH)
    http.post(f'/api/alerts/{alert_id}/status',
              json={'status': 'resolved'}, headers=AUTH)
    with sqlite3.connect(dbfile) as connection:
        connection.row_factory = sqlite3.Row
        rows = [dict(row) for row in connection.execute(
            'SELECT from_status, to_status, source FROM investigation_events '
            'WHERE alert_id = ? ORDER BY id', (alert_id,))]
    assert [(row['from_status'], row['to_status']) for row in rows] == \
        [('new', 'investigating'), ('investigating', 'resolved')]
    assert all(row['source'] == 'api' for row in rows)


# -- untrusted data stays data (XSS safety) ----------------------------------------

def test_investigation_payload_keeps_markup_as_plain_data(client):
    http, dbfile, _ = client
    with sqlite3.connect(dbfile) as connection:
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details, investigation_status) "
            "VALUES ('2025-01-01T00:00:00Z', 'PORT_SCAN', 'MEDIUM', "
            "'<script>alert(1)</script><img src=x onerror=alert(2)>', 'new')")
        connection.commit()
        xss_id = connection.execute(
            'SELECT id FROM alerts WHERE details LIKE "<script>%"').fetchone()[0]
    response = http.get(f'/api/alerts/{xss_id}/investigation')
    assert response.status_code == 200
    assert response.content_type.startswith('application/json')
    payload = response.get_json()
    # The markup is delivered as inert JSON data, never as HTML.
    assert payload['alert']['details'].startswith('<script>')
    assert b'<html' not in response.data.lower()
    timeline = http.get(f'/api/alerts/{xss_id}/timeline').get_json()
    assert timeline['alert_id'] == xss_id
    hunt = http.get('/api/hunt?user=alice').get_json()
    assert isinstance(hunt['results'], list)
