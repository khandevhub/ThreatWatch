"""Flask dashboard/API tests."""
import sqlite3

import pytest

import app as app_module
from app import app


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    dbfile = tmp_path / 'test_db.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    # app reads DB_FILE into a module constant at import; bind it explicitly
    # so the endpoints hit this test's database.
    app_module.DB = str(dbfile)
    conn = sqlite3.connect(str(dbfile))
    try:
        conn.execute(
            'CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, '
            'rule TEXT, severity TEXT, details TEXT)')
        conn.executemany(
            'INSERT INTO alerts (time, rule, severity, details) VALUES (?, ?, ?, ?)',
            [
                ('2025-01-01T10:00:00', 'BRUTE_FORCE', 'HIGH',
                 'Multiple failed logins from 1.2.3.4: 5 attempts [KNOWN_SCANNER]'),
                ('2025-01-01T10:00:05', 'PORT_SCAN', 'MEDIUM',
                 'Port scan detected from 9.9.9.9 - ports: [22, 80]'),
            ])
        conn.commit()
    finally:
        conn.close()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client, dbfile


def test_index_page_serves(api_client):
    client, _ = api_client
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'ThreatWatch' in resp.data


def test_alerts_endpoint_returns_rows(api_client):
    client, dbfile = api_client
    resp = client.get('/api/alerts')
    assert resp.status_code == 200
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
