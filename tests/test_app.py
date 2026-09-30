"""Flask dashboard/API tests."""
import sqlite3

import pytest

import app as app_module
from app import app

TEST_TOKEN = 'unit-test-' + 'x' * 48


@pytest.fixture()
def api_client(tmp_path):
    dbfile = tmp_path / 'test_db.sqlite'
    app.config.update(
        DB_FILE=str(dbfile),
        INGEST_TOKEN=TEST_TOKEN,
        TESTING=True,
        MAX_CONTENT_LENGTH=app_module.MAX_CONTENT_LENGTH,
    )
    app.extensions['ingest_rate_limiter'] = app_module.IngestRateLimiter()
    app_module.init_db(str(dbfile))
    with sqlite3.connect(str(dbfile)) as conn:
        conn.executemany(
            'INSERT INTO alerts (time, rule, severity, details) VALUES (?, ?, ?, ?)',
            [
                ('2025-01-01T10:00:00', 'BRUTE_FORCE', 'HIGH',
                 'Multiple failed logins from 1.2.3.4: 5 attempts [KNOWN_SCANNER]'),
                ('2025-01-01T10:00:05', 'PORT_SCAN', 'MEDIUM',
                 'Port scan detected from 9.9.9.9 - ports: [22, 80]'),
            ],
        )
    with app.test_client() as client:
        yield client, dbfile


def test_index_page_serves_with_security_headers(api_client):
    client, _ = api_client
    response = client.get('/')
    assert response.status_code == 200
    assert b'ThreatWatch' in response.data
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert "default-src 'self'" in response.headers['Content-Security-Policy']


def test_alerts_endpoint_returns_rows(api_client):
    client, dbfile = api_client
    resp = client.get('/api/alerts')
    assert resp.status_code == 200
    assert resp.headers['Cache-Control'] == 'no-store'
    data = resp.get_json()
    assert len(data) == 2
    first = data[0]  # newest first
    assert first['rule'] == 'PORT_SCAN'
    assert first['details'].startswith('Port scan detected from')


def test_summary_endpoint_counts_by_rule(api_client):
    client, _ = api_client
    resp = client.get('/api/summary')
    assert resp.status_code == 200
    summary = resp.get_json()
    assert summary == {'BRUTE_FORCE': 1, 'PORT_SCAN': 1}


def test_alert_payload_has_expected_fields(api_client):
    client, _ = api_client
    data = client.get('/api/alerts').get_json()
    assert set(data[0].keys()) == {'id', 'time', 'rule', 'severity', 'details'}
