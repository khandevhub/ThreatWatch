"""Phase 5 tests: SOAR HTTP API — auth, validation, dry-run, approvals,
cancellation, incidents, and credential isolation."""
import sqlite3

import pytest

import database
from app import create_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    dbfile = tmp_path / 'api.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    database.init_db(str(dbfile))
    token = 'x' * 32
    application = create_app({'DB_FILE': str(dbfile), 'INGEST_TOKEN': token})
    application.config['TESTING'] = True
    now = database.utc_now()
    with database.connect(str(dbfile)) as con:
        con.execute(
            "INSERT INTO alerts (time, rule, severity, details, rule_id, "
            "correlation_id, deterministic_risk_score, risk_band, "
            "jev_priority, jev_status, investigation_status, "
            "mitre_techniques_json, evidence_json, source_event_ids_json) "
            "VALUES (?, 'Brute force', 'HIGH', 'details token Bearer "
            "aaa.bbb.ccc', 'TW-001', 'corr-1', 72, 'high', 'high', 'alert', "
            "'new', '[]', '{}', '[]')", (now,))
        alert_id = con.execute('SELECT MAX(id) FROM alerts').fetchone()[0]
        con.commit()
    return application.test_client(), str(dbfile), token, alert_id


def auth(token):
    return {'Authorization': 'Bearer ' + token}


def test_playbooks_list_and_detail(client):
    test_client, _db, _token, _aid = client
    response = test_client.get('/api/playbooks')
    assert response.status_code == 200
    playbooks = response.get_json()['playbooks']
    assert {p['playbook_id'] for p in playbooks} >= {'TW-PB-001', 'TW-PB-002'}
    detail = test_client.get('/api/playbooks/TW-PB-001')
    assert detail.status_code == 200
    assert detail.get_json()['definition']['triggers'][0]['value'] == 'TW-001'
    assert test_client.get('/api/playbooks/TW-PB-999').status_code == 404


def test_execute_requires_bearer(client):
    test_client, _db, _token, alert_id = client
    response = test_client.post('/api/playbooks/TW-PB-001/execute',
                                json={'alert_id': alert_id})
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Bearer'


def test_execute_validation_errors(client):
    test_client, _db, token, alert_id = client
    headers = auth(token)
    cases = [
        ({}, 400),                       # missing alert_id
        ({'alert_id': 'one'}, 400),      # non-integer
        ({'alert_id': alert_id, 'dry_run': 'yes'}, 400),
        ({'alert_id': alert_id, 'actor': 'bad actor!'}, 400),
        ({'alert_id': 99999}, 404),      # unknown alert
    ]
    for body, expected in cases:
        response = test_client.post('/api/playbooks/TW-PB-001/execute',
                                    json=body, headers=headers)
        assert response.status_code == expected, (body, response.status_code)


def test_execute_dry_run_default_and_duplicate_conflict(client):
    test_client, _db, token, alert_id = client
    headers = auth(token)
    first = test_client.post('/api/playbooks/TW-PB-001/execute',
                             json={'alert_id': alert_id,
                                   'actor': 'analyst.jane'}, headers=headers)
    assert first.status_code == 202
    execution = first.get_json()
    assert execution['dry_run'] is True
    assert execution['state'] == 'PENDING'
    duplicate = test_client.post('/api/playbooks/TW-PB-001/execute',
                                 json={'alert_id': alert_id,
                                       'actor': 'analyst.jane'},
                                 headers=headers)
    assert duplicate.status_code == 409
    assert duplicate.get_json()['error'] == 'duplicate_execution'
    assert duplicate.get_json()['existing_execution_id'] == \
        execution['execution_id']


def test_execution_detail_and_listing(client):
    test_client, _db, token, alert_id = client
    headers = auth(token)
    created = test_client.post('/api/playbooks/TW-PB-001/execute',
                               json={'alert_id': alert_id}, headers=headers)
    execution_id = created.get_json()['execution_id']
    detail = test_client.get(f'/api/soar/executions/{execution_id}')
    assert detail.status_code == 200
    assert detail.get_json()['evidence']['evidence_id']
    listing = test_client.get('/api/soar/executions')
    assert listing.status_code == 200
    assert any(row['execution_id'] == execution_id
               for row in listing.get_json()['executions'])
    assert test_client.get('/api/soar/executions/EXE-NOPE').status_code == 404


def test_cancel_requires_auth_and_works(client):
    test_client, _db, token, alert_id = client
    headers = auth(token)
    created = test_client.post('/api/playbooks/TW-PB-001/execute',
                               json={'alert_id': alert_id}, headers=headers)
    execution_id = created.get_json()['execution_id']
    anonymous = test_client.post(
        f'/api/soar/executions/{execution_id}/cancel', json={'actor': 'a'})
    assert anonymous.status_code == 401
    cancelled = test_client.post(
        f'/api/soar/executions/{execution_id}/cancel',
        json={'actor': 'analyst.jane', 'reason': 'test'},
        headers=headers)
    assert cancelled.status_code == 200
    assert cancelled.get_json()['state'] == 'CANCELLED'
    again = test_client.post(
        f'/api/soar/executions/{execution_id}/cancel',
        json={'actor': 'analyst.jane'}, headers=headers)
    assert again.status_code == 409


def test_approval_endpoints_require_auth_and_drive_execution(client):
    test_client, db, token, alert_id = client
    headers = auth(token)
    created = test_client.post('/api/playbooks/TW-PB-001/execute',
                               json={'alert_id': alert_id, 'dry_run': False,
                                     'actor': 'analyst.jane'},
                               headers=headers)
    execution_id = created.get_json()['execution_id']
    # Pending approval exists (real-mode start auto-advances).
    listing = test_client.get('/api/soar/approvals?decision=pending')
    assert listing.status_code == 200
    approvals = listing.get_json()['approvals']
    assert len(approvals) == 1
    approval_id = approvals[0]['approval_id']
    # Anonymous decision rejected.
    anonymous = test_client.post(
        f'/api/soar/approvals/{approval_id}/approve',
        json={'approver': 'analyst.jane'})
    assert anonymous.status_code == 401
    # Invalid approver rejected.
    invalid = test_client.post(
        f'/api/soar/approvals/{approval_id}/approve',
        json={'approver': 'bad actor!'}, headers=headers)
    assert invalid.status_code == 400
    # Rejection drives the execution to a terminal state.
    rejected = test_client.post(
        f'/api/soar/approvals/{approval_id}/reject',
        json={'approver': 'analyst.bob', 'reason': 'benign'},
        headers=headers)
    assert rejected.status_code == 200
    assert rejected.get_json()['state'] == 'APPROVAL_REJECTED'
    # Second decision on the same approval conflicts.
    repeat = test_client.post(
        f'/api/soar/approvals/{approval_id}/approve',
        json={'approver': 'analyst.bob'}, headers=headers)
    assert repeat.status_code == 409
    # Audit trail is exposed per execution.
    audit = test_client.get(f'/api/soar/executions/{execution_id}/audit')
    assert audit.status_code == 200
    events = [row['event_type'] for row in audit.get_json()['audit']]
    assert 'approval_decision' in events
    assert test_client.get('/api/soar/executions/EXE-NOPE/audit').status_code \
        == 404


def test_incidents_endpoints(client):
    test_client, db, token, alert_id = client
    headers = auth(token)
    empty = test_client.get('/api/incidents')
    assert empty.status_code == 200
    assert empty.get_json()['incidents'] == []
    created = test_client.post('/api/playbooks/TW-PB-001/execute',
                               json={'alert_id': alert_id, 'dry_run': False,
                                     'actor': 'analyst.jane'},
                               headers=headers)
    execution_id = created.get_json()['execution_id']
    pending = test_client.get('/api/soar/approvals?decision=pending')
    approval_id = pending.get_json()['approvals'][0]['approval_id']
    approved = test_client.post(
        f'/api/soar/approvals/{approval_id}/approve',
        json={'approver': 'analyst.jane'}, headers=headers)
    assert approved.status_code == 200
    incidents = test_client.get('/api/incidents').get_json()['incidents']
    assert len(incidents) == 1
    incident_id = incidents[0]['incident_id']
    detail = test_client.get(f'/api/incidents/{incident_id}')
    assert detail.status_code == 200
    assert alert_id in detail.get_json()['alert_ids']
    assert test_client.get('/api/incidents/INC-NOPE').status_code == 404
    assert test_client.get(f'/api/soar/executions/{execution_id}') \
        .get_json()['state'] == 'SUCCEEDED'


def test_no_credentials_in_responses(client):
    test_client, _db, token, alert_id = client
    headers = auth(token)
    created = test_client.post('/api/playbooks/TW-PB-001/execute',
                               json={'alert_id': alert_id}, headers=headers)
    body = created.get_data(as_text=True)
    assert token not in body
    assert 'authorization' not in body.lower()
