"""SOC alert model: persisted fields, API exposure, investigation lifecycle."""
import sqlite3

import pytest

import detector
from app import INVESTIGATION_STATUSES, create_app, get_alerts, set_investigation_status
from detector import process_event


@pytest.fixture()
def soc_db(tmp_path, monkeypatch):
    dbfile = tmp_path / 'soc.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    detector.DB = str(dbfile)
    detector.bad_ips = {}
    detector.init_db(str(dbfile))
    return dbfile


def _latest_alert(dbfile):
    with sqlite3.connect(str(dbfile)) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            'SELECT * FROM alerts ORDER BY id DESC LIMIT 1').fetchone()


def test_bruteforce_alert_carries_soc_fields(soc_db):
    for _ in range(5):
        process_event({'type': 'auth_failed', 'src': '1.2.3.4', 'user': 'root'})
    row = _latest_alert(soc_db)
    assert row['rule'] == 'BRUTE_FORCE'
    assert row['rule_id'] == 'TW-001'
    assert row['detection_id']
    assert row['deterministic_risk_score'] is not None
    assert 0 <= row['deterministic_risk_score'] <= 100
    assert row['risk_band'] in ('low', 'medium', 'high', 'critical')
    factors = sqlite3.connect(str(soc_db)).execute(
        "SELECT risk_factors_json FROM alerts WHERE id = ?", (row['id'],)).fetchone()[0]
    assert 'severity' in factors and 'threat_intel' in factors
    assert row['risk_explanation']
    assert row['correlation_id']
    assert row['investigation_status'] == 'new'
    event_ids = sqlite3.connect(str(soc_db)).execute(
        "SELECT source_event_ids_json FROM alerts WHERE id = ?",
        (row['id'],)).fetchone()[0]
    assert 'e-' in event_ids or '[' in event_ids  # JSON list of source event IDs


def test_soc_fields_reference_real_events(soc_db):
    payload = {'event_id': 'soc-e2e-1', 'type': 'auth_failed', 'src': '1.2.3.4',
               'user': 'root'}
    for _ in range(5):
        process_event(dict(payload, event_id='soc-e2e-' + str(_ + 1)))
    row = _latest_alert(soc_db)
    event_ids = sqlite3.connect(str(soc_db)).execute(
        'SELECT source_event_ids_json FROM alerts WHERE id = ?', (row['id'],)
    ).fetchone()[0]
    import json
    listed = json.loads(event_ids)
    assert {'soc-e2e-1', 'soc-e2e-5'} <= set(listed)
    with sqlite3.connect(str(soc_db)) as connection:
        stored = {r[0] for r in connection.execute('SELECT event_id FROM events')}
    assert set(listed) <= stored


def test_process_alert_fires_port_scan_with_soc_fields(soc_db):
    process_event({'type': 'port_scan', 'src': '9.9.9.9', 'ports': [22, 80]})
    row = _latest_alert(soc_db)
    assert row['rule'] == 'PORT_SCAN'
    assert row['deterministic_risk_score'] is not None
    mitre = sqlite3.connect(str(soc_db)).execute(
        'SELECT mitre_techniques_json FROM alerts WHERE id = ?', (row['id'],)
    ).fetchone()[0]
    assert 'T1046' in mitre


TOKEN = 'soc-status-test-' + 'x' * 48


@pytest.fixture()
def api(soc_db):
    application = create_app({
        'DB_FILE': str(soc_db), 'INGEST_TOKEN': TOKEN, 'TESTING': True,
    })
    return application.test_client(), soc_db


def test_api_alerts_expose_soc_fields(api):
    client, dbfile = api
    for _ in range(5):
        process_event({'type': 'auth_failed', 'src': '1.2.3.4', 'user': 'root'})
    alerts = client.get('/api/alerts').get_json()
    alert = alerts[0]
    assert alert['rule'] == 'BRUTE_FORCE'
    assert isinstance(alert['deterministic_risk_score'], int)
    assert alert['risk_factors']['severity'] == 30
    assert alert['mitre_techniques'] == ['T1110']
    assert alert['investigation_required'] is True
    assert alert['source_event_ids']
    assert alert['correlation_id']


def test_investigation_status_requires_token(api):
    client, _ = api
    response = client.post('/api/alerts/1/status', json={'status': 'in_progress'})
    assert response.status_code == 401


def test_investigation_status_round_trip(api):
    client, dbfile = api
    process_event({'type': 'port_scan', 'src': '9.9.9.9', 'ports': [22]})
    alert_id = get_alerts(1, str(dbfile))[0]['id']
    headers = {'Authorization': 'Bearer ' + TOKEN}
    # Phase 2 alias inputs remain accepted and canonicalize on storage.
    ok = client.post(f'/api/alerts/{alert_id}/status',
                     json={'status': 'in_progress'}, headers=headers)
    assert ok.status_code == 200
    alerts = client.get('/api/alerts').get_json()
    assert alerts[0]['investigation_status'] == 'investigating'

    closed = client.post(f'/api/alerts/{alert_id}/status',
                         json={'status': 'closed'}, headers=headers)
    assert closed.status_code == 200
    alerts = client.get('/api/alerts').get_json()
    assert alerts[0]['investigation_status'] == 'resolved'

    bad = client.post(f'/api/alerts/{alert_id}/status',
                      json={'status': 'bogus'}, headers=headers)
    assert bad.status_code == 400
    missing = client.post('/api/alerts/99999/status',
                          json={'status': 'resolved'}, headers=headers)
    assert missing.status_code == 404


def test_invalid_status_rejected_at_model_layer(soc_db):
    with pytest.raises(ValueError):
        set_investigation_status(1, 'nonsense', str(soc_db))
    assert INVESTIGATION_STATUSES == ('new', 'investigating', 'resolved', 'dismissed')
