"""Phase 3 end-to-end: ingest -> alerts -> investigation -> timeline -> hunt
-> lifecycle -> advisory AI perspective, over one shared database."""
import json
import sqlite3

import pytest

import detector


TOKEN = 'phase3-e2e-' + 'x' * 48
AUTH = {'Authorization': 'Bearer ' + TOKEN}


@pytest.fixture()
def e2e(tmp_path, monkeypatch):
    dbfile = tmp_path / 'e2e.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    intel = tmp_path / 'intel.csv'
    intel.write_text('ip,tag,confidence,source\n'
                     '203.0.113.66,spray_source,0.95,e2e-feed\n', encoding='utf-8')
    monkeypatch.setenv('THREAT_INTEL', str(intel))
    detector.DB = str(dbfile)
    detector.bad_ips = {}
    detector.reload_soc_components({})
    detector.init_db(str(dbfile))
    from app import create_app
    application = create_app({
        'DB_FILE': str(dbfile), 'INGEST_TOKEN': TOKEN, 'TESTING': True,
    })
    with application.test_client() as test_client:
        yield test_client, str(dbfile), application


def _alert_id(dbfile, rule):
    with sqlite3.connect(dbfile) as connection:
        return connection.execute(
            'SELECT id FROM alerts WHERE rule = ? ORDER BY id DESC LIMIT 1',
            (rule,)).fetchone()[0]


def test_phase3_end_to_end_flow(e2e):
    client, dbfile, _ = e2e

    # -- 1. Ingestion produces a merged spray+brute-force SOC alert ------------
    event_ids = []
    for round_no in range(2):
        for user in ('alice', 'bob', 'carol'):
            event_id = f'e2e-{round_no}-{user}'
            event_ids.append(event_id)
            response = client.post('/api/ingest', headers=AUTH, json={
                'event_id': event_id, 'type': 'auth_failed',
                'src': '203.0.113.66', 'user': user})
            assert response.status_code == 202, response.get_json()
    alert_id = _alert_id(dbfile, 'PASSWORD_SPRAYING')

    # -- 2. Alert surface keeps Phase 1/2 fields and Phase 3 status ------------
    alerts = client.get('/api/alerts').get_json()
    spray = next(row for row in alerts if row['id'] == alert_id)
    assert spray['rule_id'] == 'TW-004'
    assert spray['investigation_status'] == 'new'
    assert spray['deterministic_risk_score'] is not None
    assert 'T1110.003' in spray['mitre_techniques']

    # -- 3. Investigation package assembles all sections ------------------------
    package = client.get(f'/api/alerts/{alert_id}/investigation').get_json()
    assert package['alert']['alert_id'] == alert_id
    assert package['evidence']['rule_code'] == 'PASSWORD_SPRAYING'
    assert '203.0.113.66' in package['evidence']['entities']['source_ips']
    assert {'alice', 'bob', 'carol'} <= set(package['evidence']['entities']['usernames'])
    assert package['evidence']['event_count'] == len(package['evidence']['event_ids'])
    assert package['timeline']['total_events'] == package['evidence']['event_count']
    indicators = {item['indicator']: item
                  for item in package['indicators']['indicators']}
    assert indicators['203.0.113.66']['known_malicious'] is True
    assert any(match.get('indicator') == '203.0.113.66' and
               match.get('confidence') == 0.95
               for match in package['threat_intel']['matches'])
    technique_ids = {item['technique_id'] for item in package['mitre']['techniques']}
    assert 'T1110.003' in technique_ids
    assert package['related_alerts']['alerts']
    assert package['investigation_questions']
    assert package['risk']['score'] == spray['deterministic_risk_score']
    # Advisory AI layer: disabled by default.
    assert package['ai_perspective']['status'] == 'disabled'

    # -- 4. Timeline endpoint serves the ordered evidence -----------------------
    timeline = client.get(f'/api/alerts/{alert_id}/timeline').get_json()
    assert timeline['alert_id'] == alert_id
    assert timeline['timeline']['total_events'] >= 3
    entries = timeline['timeline']['entries']
    assert all(entry['event_id'] in event_ids for entry in entries)

    # -- 5. Hunting finds the alert's telemetry, by content and by linkage ------
    by_ip = client.get('/api/hunt?src_ip=203.0.113.66').get_json()
    assert by_ip['total'] >= 3
    by_alert = client.get(f'/api/hunt?alert_id={alert_id}').get_json()
    assert {row['event_id'] for row in by_alert['results']} <= set(event_ids)
    by_technique = client.get('/api/hunt?technique=T1110.003').get_json()
    assert by_technique['total'] >= 3
    bad = client.get('/api/hunt?src_ip=999.9.9.9')
    assert bad.status_code == 400

    # -- 6. Lifecycle transitions, aliases, and audit ---------------------------
    status = client.post(f'/api/alerts/{alert_id}/status',
                         json={'status': 'in_progress'}, headers=AUTH)
    assert status.status_code == 200
    assert status.get_json()['status'] == 'investigating'
    resolved = client.post(f'/api/alerts/{alert_id}/status',
                           json={'status': 'closed'}, headers=AUTH)
    assert resolved.status_code == 200
    assert client.post(f'/api/alerts/{alert_id}/status',
                       json={'status': 'new'},
                       headers=AUTH).status_code == 409
    with sqlite3.connect(dbfile) as connection:
        rows = connection.execute(
            'SELECT from_status, to_status FROM investigation_events '
            'WHERE alert_id = ? ORDER BY id', (alert_id,)).fetchall()
    assert [(row[0], row[1]) for row in rows] == \
        [('new', 'investigating'), ('investigating', 'resolved')]
    alerts = client.get('/api/alerts').get_json()
    spray = next(row for row in alerts if row['id'] == alert_id)
    assert spray['investigation_status'] == 'resolved'

    # -- 7. Advisory AI perspective turns on via env and stays offline ----------
    import os
    os.environ['INVESTIGATION_AI_ENABLED'] = '1'
    try:
        package = client.get(f'/api/alerts/{alert_id}/investigation').get_json()
    finally:
        os.environ.pop('INVESTIGATION_AI_ENABLED', None)
    perspective = package['ai_perspective']
    assert perspective['status'] == 'ok'
    assert perspective['provider'] == 'mock'
    assert perspective['advisory_only'] is True
    assert perspective['summary'] and perspective['hypotheses']
    # Hypotheses derive only from the package: the mocked intel feed values and
    # no invented network data.
    assert any('203.0.113.66' in hypothesis for hypothesis in perspective['hypotheses'])
    json.dumps(package)  # fully serializable for downstream consumers


def test_phase3_e2e_rejects_unauthenticated_investigation_writes(e2e):
    client, dbfile, _ = e2e
    for user in ('u1', 'u2', 'u3'):
        assert client.post('/api/ingest', headers=AUTH, json={
            'event_id': f'auth-e2e-{user}', 'type': 'auth_failed',
            'src': '203.0.113.70', 'user': user}).status_code == 202
    alert_id = _alert_id(dbfile, 'PASSWORD_SPRAYING')
    # Investigation reads are unauthenticated like the other read endpoints;
    # every write path requires the bearer token.
    assert client.post(f'/api/alerts/{alert_id}/status',
                       json={'status': 'investigating'}).status_code == 401
    with sqlite3.connect(dbfile) as connection:
        status = connection.execute(
            'SELECT investigation_status FROM alerts WHERE id = ?',
            (alert_id,)).fetchone()[0]
    assert status == 'new'
