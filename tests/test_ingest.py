"""Authentication, validation, and bounded-ingest API tests."""
import json
import sqlite3

import pytest

from app import IngestRateLimiter, create_app

TOKEN = 'test-token-' + 'x' * 48


@pytest.fixture()
def ingest_client(tmp_path):
    dbfile = tmp_path / 'ingest.sqlite'
    application = create_app({
        'DB_FILE': str(dbfile),
        'INGEST_TOKEN': TOKEN,
        'TESTING': True,
        'MAX_CONTENT_LENGTH': 1024,
    })
    with application.test_client() as client:
        yield client, dbfile, application


def _headers(token=TOKEN):
    return {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}


def test_ingest_requires_bearer_token(ingest_client):
    client, dbfile, _ = ingest_client
    response = client.post('/api/ingest', json={'type': 'port_scan', 'src': '9.9.9.9'})
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Bearer'
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0


def test_ingest_rejects_wrong_token(ingest_client):
    client, _, _ = ingest_client
    response = client.post(
        '/api/ingest', json={'type': 'port_scan', 'src': '9.9.9.9'},
        headers=_headers('wrong-token-' + 'x' * 48),
    )
    assert response.status_code == 401
    assert response.get_json()['error'] == 'invalid_credentials'


def test_valid_ingest_is_normalized_detected_and_idempotent(ingest_client):
    client, dbfile, _ = ingest_client
    payload = {
        'event_id': 'ingest-test-1',
        'type': 'port_scan',
        'time': '2025-01-01T01:00:00+01:00',
        'src': '9.9.9.9',
        'ports': [22, 443],
    }
    accepted = client.post('/api/ingest', json=payload, headers=_headers())
    duplicate = client.post('/api/ingest', json=payload, headers=_headers())

    assert accepted.status_code == 202
    assert accepted.get_json() == {'event_id': 'ingest-test-1', 'duplicate': False}
    assert duplicate.status_code == 200
    assert duplicate.get_json()['duplicate'] is True
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1
        event = connection.execute(
            'SELECT event_time, source_type, src_ip, metadata_json FROM events').fetchone()
        assert event[0] == '2025-01-01T00:00:00.000000Z'
        assert event[1:3] == ('network', '9.9.9.9')
        assert json.loads(event[3])['ports'] == [22, 443]
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 1
    assert client.get('/api/summary').get_json() == {'PORT_SCAN': 1}


def test_ingest_rejects_malformed_json_and_events(ingest_client):
    client, _, _ = ingest_client
    malformed_json = client.post(
        '/api/ingest', data=b'{not json', headers=_headers())
    invalid_event = client.post(
        '/api/ingest',
        json={'event_id': 'invalid-event', 'type': 'port_scan', 'src': 'not-an-ip'},
        headers=_headers(),
    )

    assert malformed_json.status_code == 400
    assert malformed_json.get_json()['error'] == 'invalid_json'
    assert invalid_event.status_code == 400
    assert invalid_event.get_json()['error'] == 'invalid_event'


def test_ingest_requires_json_and_enforces_payload_limit(ingest_client):
    client, _, application = ingest_client
    wrong_type = client.post(
        '/api/ingest', data='not-json', headers={'Authorization': 'Bearer ' + TOKEN})
    application.config['MAX_CONTENT_LENGTH'] = 64
    oversized = client.post(
        '/api/ingest', data=json.dumps({'type': 'port_scan', 'padding': 'x' * 100}),
        headers=_headers(),
    )

    assert wrong_type.status_code == 415
    assert oversized.status_code == 413
    assert oversized.get_json()['error'] == 'payload_too_large'


def test_ingest_is_disabled_without_a_server_secret(tmp_path, monkeypatch):
    monkeypatch.delenv('INGEST_TOKEN', raising=False)
    monkeypatch.delenv('INGEST_TOKEN_FILE', raising=False)
    application = create_app({'DB_FILE': str(tmp_path / 'disabled.sqlite'), 'TESTING': True})
    response = application.test_client().post(
        '/api/ingest', json={'type': 'port_scan', 'src': '9.9.9.9'})
    assert response.status_code == 503
    assert response.get_json()['error'] == 'ingestion_disabled'


def test_ingest_rate_limit_returns_429(ingest_client):
    client, _, application = ingest_client
    application.extensions['ingest_rate_limiter'] = IngestRateLimiter(limit=1)
    first = client.post(
        '/api/ingest', json={'event_id': 'rate-1', 'type': 'port_scan'}, headers=_headers())
    second = client.post(
        '/api/ingest', json={'event_id': 'rate-2', 'type': 'port_scan'}, headers=_headers())
    assert first.status_code == 202
    assert second.status_code == 429
    assert second.headers['Retry-After'] == '60'


def test_ingest_rate_limits_authentication_attempts(ingest_client):
    client, _, application = ingest_client
    application.extensions['ingest_rate_limiter'] = IngestRateLimiter(limit=1)
    first = client.post('/api/ingest', json={'type': 'port_scan'})
    second = client.post('/api/ingest', json={'type': 'port_scan'})
    assert first.status_code == 401
    assert second.status_code == 429


def test_ingest_requires_event_id(ingest_client):
    client, _, _ = ingest_client
    response = client.post(
        '/api/ingest', json={'type': 'port_scan'}, headers=_headers())
    assert response.status_code == 400
    assert response.get_json()['error'] == 'event_id_required'


def test_reusing_event_id_for_different_data_returns_conflict(ingest_client):
    client, dbfile, _ = ingest_client
    first = client.post('/api/ingest', json={
        'event_id': 'collision-1', 'type': 'port_scan', 'src': '9.9.9.9',
    }, headers=_headers())
    second = client.post('/api/ingest', json={
        'event_id': 'collision-1', 'type': 'port_scan', 'src': '8.8.8.8',
    }, headers=_headers())
    assert first.status_code == 202
    assert second.status_code == 409
    assert second.get_json()['error'] == 'event_id_conflict'
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1


def test_short_configured_token_fails_closed(tmp_path):
    with pytest.raises(ValueError, match='32 to 4096 characters'):
        create_app({'DB_FILE': str(tmp_path / 'short.sqlite'), 'INGEST_TOKEN': 'short'})
