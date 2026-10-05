"""Tests for the SOC analyst experience polish: attack replay, analyst
cases, decision explanation, and the HTML investigation report.

Everything runs offline against the real pipeline; no AI provider and no
network is involved. These tests complement (never weaken) the existing
SOC integration suite.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

import database
import soc_cases
import soc_report
import soc_replay
import soc_simulation

PROJECT_ROOT = Path(__file__).resolve().parents[1]

TOKEN = 'x' * 32
BEARER = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    dbfile = tmp_path / 'soc.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    # AI provider state must not depend on the developer's own environment.
    monkeypatch.delenv('AI_LLM_PROVIDER', raising=False)
    database.init_db(str(dbfile))
    from app import create_app
    application = create_app({
        'DB_FILE': str(dbfile),
        'INGEST_TOKEN': TOKEN,
        'TESTING': True,
        'KNOWLEDGE_DB_FILE': str(tmp_path / 'kb.sqlite'),
    })
    return application.test_client(), str(dbfile)


def _run_brute_force(client, scenario='brute_force'):
    response = client.post(
        f'/api/simulation/scenarios/{scenario}/generate', headers=BEARER)
    assert response.status_code == 201
    run = response.get_json()
    response = client.post(
        f'/api/simulation/scenarios/{scenario}/process', headers=BEARER,
        json={'run_id': run['run_id']})
    assert response.status_code == 200
    return response.get_json()['run']


# ---------------------------------------------------------------------------
# Attack replay
# ---------------------------------------------------------------------------

def test_replay_steps_through_real_pipeline(tmp_path):
    db = str(tmp_path / 'replay.sqlite')
    database.init_db(db)
    run = soc_simulation.create_run('brute_force', db_file=db)
    assert run['status'] == 'generated'
    replay = soc_replay.start_replay(run['run_id'], db_file=db)
    assert replay['total_events'] == run['event_count']
    assert replay['status'] == 'running'
    alert_steps = []
    while True:
        view, step = soc_replay.replay_step(replay['replay_id'], db_file=db)
        if step is None:
            break
        assert step['remaining'] >= 0
        if step['alert_ids']:
            alert_steps.append(step)
    assert view['status'] == 'complete'
    # Detection fired through the real pipeline exactly as batch processing.
    assert len(alert_steps) == 1
    # TW-001 threshold is 5 failures → detection fires on the fifth event
    # (index 4), not on the last replay step.
    assert alert_steps[0]['event_index'] == 4
    alerts = alert_steps[0]['alert_ids']
    with database.connect(db) as connection:
        row = connection.execute(
            'SELECT rule_id, severity, deterministic_risk_score FROM alerts '
            'WHERE id = ?', (alerts[0],)).fetchone()
    assert row['rule_id'] == 'TW-001'
    assert row['severity'] == 'HIGH'


def test_replay_rejects_processed_run_and_bad_delay(tmp_path):
    db = str(tmp_path / 'replay2.sqlite')
    database.init_db(db)
    run = soc_simulation.create_run('brute_force', db_file=db)
    soc_simulation.process_run(run['run_id'], db_file=db)
    with pytest.raises(soc_replay.ReplayError):
        soc_replay.start_replay(run['run_id'], db_file=db)
    fresh = soc_simulation.create_run('port_scan', db_file=db)
    with pytest.raises(soc_replay.ReplayError):
        soc_replay.start_replay(fresh['run_id'], step_delay_ms=99999,
                                db_file=db)
    with pytest.raises(soc_replay.ReplayError):
        soc_replay.start_replay('SIMR-doesnotexist', db_file=db)


def test_replay_endpoints_require_bearer_and_work(app_client):
    client, _db = app_client
    run = _run_brute_force(client)
    denied = client.post('/api/simulation/replay', json={'run_id': run['run_id']})
    assert denied.status_code == 401
    # Replay needs a generated (not yet processed) run.
    fresh = client.post('/api/simulation/scenarios/brute_force/generate',
                        headers=BEARER).get_json()
    response = client.post('/api/simulation/replay', headers=BEARER,
                           json={'run_id': fresh['run_id'], 'step_delay_ms': 100})
    assert response.status_code == 201
    replay = response.get_json()
    assert replay['total_events'] == run['event_count']
    detail = client.get(f"/api/simulation/replays/{replay['replay_id']}")
    assert detail.status_code == 200
    assert detail.get_json()['scenario_id'] == 'brute_force'
    stepped = client.post(f"/api/simulation/replays/{replay['replay_id']}/step",
                          headers=BEARER)
    assert stepped.status_code == 200
    assert stepped.get_json()['step']['event_index'] == 0
    missing = client.post('/api/simulation/replays/RPL-zzz/step', headers=BEARER)
    assert missing.status_code == 404


# ---------------------------------------------------------------------------
# Analyst case workflow
# ---------------------------------------------------------------------------

def _open_case(client, alert_id):
    response = client.post(f'/api/alerts/{alert_id}/incident', headers=BEARER)
    assert response.status_code == 201, response.get_data()
    incident_id = response.get_json()['incident_id']
    response = client.post(f'/api/incidents/{incident_id}/case', headers=BEARER,
                           json={})
    assert response.status_code == 201
    return response.get_json()


def test_case_full_workflow_with_notes_and_audit(app_client):
    client, db = app_client
    run = _run_brute_force(client)
    alert_id = run['alert_ids'][0]
    case = _open_case(client, alert_id)
    assert case['status'] == 'new'
    assert case['alert_id'] == alert_id

    # Idempotent reopen: same case, no duplicates.
    again = client.post(f"/api/incidents/{case['incident_id']}/case",
                        headers=BEARER, json={})
    assert again.status_code == 201
    assert again.get_json()['case_id'] == case['case_id']

    # Decision without a note is rejected.
    response = client.post(f"/api/cases/{case['case_id']}/transition",
                           headers=BEARER, json={'to_state': 'confirmed_threat'})
    assert response.status_code == 400

    response = client.post(f"/api/cases/{case['case_id']}/transition",
                           headers=BEARER,
                           json={'to_state': 'investigating'})
    assert response.status_code == 200
    assert response.get_json()['status'] == 'investigating'

    response = client.post(f"/api/cases/{case['case_id']}/notes", headers=BEARER,
                           json={'note': 'Timeline shows 7 failures from one IP'})
    assert response.status_code == 201

    response = client.post(f"/api/cases/{case['case_id']}/transition",
                           headers=BEARER,
                           json={'to_state': 'confirmed_threat',
                                 'note': 'Confidence high: single source, one target'})
    assert response.status_code == 200
    body = response.get_json()
    assert body['status'] == 'confirmed_threat'
    assert body['decision'] == 'confirmed_threat'
    assert any('Confidence high' in note['body'] for note in body['notes'])

    response = client.post(f"/api/cases/{case['case_id']}/transition",
                           headers=BEARER,
                           json={'to_state': 'closed', 'note': 'done'})
    assert response.status_code == 200
    assert response.get_json()['status'] == 'closed'

    # Closed is terminal.
    response = client.post(f"/api/cases/{case['case_id']}/transition",
                           headers=BEARER, json={'to_state': 'investigating'})
    assert response.status_code == 400

    # Every workflow step audited in the shared soar_audit trail.
    with database.connect(db) as connection:
        rows = connection.execute(
            "SELECT event_type, actor, alert_id FROM soar_audit "
            "WHERE event_type LIKE 'case_%' ORDER BY id").fetchall()
    types = [row['event_type'] for row in rows]
    # 'Confirmed threat' carries a decision note, and closing stores the
    # closing note — both are audited alongside the transitions.
    assert types == ['case_opened', 'case_state_transition', 'case_note_added',
                     'case_state_transition', 'case_note_added',
                     'case_state_transition', 'case_note_added']
    assert all(row['actor'] == 'analyst' for row in rows)
    assert all(row['alert_id'] == alert_id for row in rows)


def test_case_for_alert_lookup_and_false_positive_path(app_client):
    client, db = app_client
    run = _run_brute_force(client)
    alert_id = run['alert_ids'][0]
    assert soc_cases.case_for_alert(alert_id, db_file=db) is None
    case = _open_case(client, alert_id)
    found = soc_cases.case_for_alert(alert_id, db_file=db)
    assert found is not None and found['case_id'] == case['case_id']
    response = client.get(f'/api/alerts/{alert_id}/case')
    assert response.status_code == 200
    assert response.get_json()['case']['case_id'] == case['case_id']

    response = client.post(f"/api/cases/{case['case_id']}/transition",
                           headers=BEARER,
                           json={'to_state': 'false_positive',
                                 'note': 'Legitimate backup job'})
    assert response.status_code == 200
    assert response.get_json()['decision'] == 'false_positive'


def test_case_transitions_reject_unknown_states(app_client):
    client, _db = app_client
    run = _run_brute_force(client)
    case = _open_case(client, run['alert_ids'][0])
    for bad in ('bogus', 'resolved'):
        response = client.post(f"/api/cases/{case['case_id']}/transition",
                               headers=BEARER, json={'to_state': bad})
        assert response.status_code == 400
    response = client.post('/api/cases/CASE-zzz/transition', headers=BEARER,
                           json={'to_state': 'investigating'})
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Decision explanation (WHY panel data)
# ---------------------------------------------------------------------------

def test_decision_explanation_uses_stored_values(app_client):
    client, db = app_client
    run = _run_brute_force(client)
    alert_id = run['alert_ids'][0]
    response = client.get(f'/api/alerts/{alert_id}/decision')
    assert response.status_code == 200
    data = response.get_json()
    assert data['identity']['rule_id'] == 'TW-001'
    assert data['identity']['severity'] == 'HIGH'
    assert data['identity']['risk_score'] == 39
    assert data['identity']['source_ips'] == ['203.0.113.10']
    # Hosts come from the contributing stored events (windowed rule evidence
    # does not carry the hostname itself).
    assert data['identity']['hostnames'] == ['db-lab-01']
    assert data['detection']['matched_events'] == len(
        data['detection']['source_event_ids'])
    assert data['mitre']['techniques'] == ['T1110']
    assert data['risk']['factors']['severity'] == 30
    assert sum(data['risk']['factors'].values()) == data['risk']['score']
    # Honest absence: AI was never run, Jev is the deterministic fallback.
    assert data['ai']['status'] == 'disabled'
    assert data['jev']['status'] == 'fallback'
    assert data['case'] is None
    assert data['soar']['executions'] == []


def test_decision_explanation_reflects_case_and_ai_result(app_client):
    client, db = app_client
    run = _run_brute_force(client)
    alert_id = run['alert_ids'][0]
    case = _open_case(client, alert_id)
    # Simulate a stored AI result row (as the AI endpoint would persist).
    with database.connect(db) as connection:
        connection.execute(
            'INSERT INTO ai_investigation_results (alert_id, '
            'ai_schema_version, status, response_json, created_at, '
            'updated_at) VALUES (?,?,?,?,?,?)',
            (alert_id, '1', 'ok', json.dumps({
                'summary': 'Brute force pattern confirmed',
                'assessment': 'consistent with attack',
            }), '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'))
        connection.commit()
    data = soc_report.build_decision_explanation(alert_id, db_file=db)
    assert data['ai']['status'] == 'ok'
    assert data['ai']['summary'] == 'Brute force pattern confirmed'
    assert data['case']['case_id'] == case['case_id']


def test_decision_explanation_with_soar_history(app_client):
    """Regression: with a live SOAR execution for the alert, the explanation
    query joins soar_approvals — the approval timestamp column must match the
    real schema (browser E2E caught an HTTP 500 here)."""
    client, db = app_client
    run = _run_brute_force(client)
    alert_id = run['alert_ids'][0]
    response = client.post('/api/playbooks/TW-PB-001/execute',
                           json={'alert_id': alert_id, 'actor': 'analyst.jane'},
                           headers=BEARER)
    assert response.status_code == 202
    execution = response.get_json()
    state = execution['state']
    for _ in range(4):
        if state == 'WAITING_APPROVAL':
            break
        advanced = client.post(
            f"/api/soar/executions/{execution['execution_id']}/advance",
            json={'actor': 'analyst.jane'}, headers=BEARER)
        assert advanced.status_code == 200
        state = advanced.get_json()['state']
    assert state == 'WAITING_APPROVAL'
    data = soc_report.build_decision_explanation(alert_id, db_file=db)
    assert data['soar']['executions'][0]['execution_id'] == \
        execution['execution_id']
    assert data['soar']['approvals'], 'approval rows must be returned'
    assert all(row['execution_id'] == execution['execution_id']
               for row in data['soar']['approvals'])


def test_case_audit_visible_in_alert_bundle_and_global_view(app_client):
    """Case decisions must surface in the console audit trail: the per-alert
    SOAR bundle and the global case-audit endpoint (browser E2E gap)."""
    client, _db = app_client
    run = _run_brute_force(client)
    alert_id = run['alert_ids'][0]
    case = _open_case(client, alert_id)
    response = client.post(f"/api/cases/{case['case_id']}/transition",
                           headers=BEARER,
                           json={'to_state': 'investigating', 'analyst': 'analyst'})
    assert response.status_code == 200
    response = client.post(f"/api/cases/{case['case_id']}/transition",
                           headers=BEARER,
                           json={'to_state': 'confirmed_threat', 'analyst': 'analyst',
                                 'note': 'threshold exceeded, confirming'})
    assert response.status_code == 200

    full = client.get(f'/api/soc/alerts/{alert_id}/full')
    assert full.status_code == 200
    audit = full.get_json()['soar']['audit']
    case_events = [row['event_type'] for row in audit
                   if row['event_type'].startswith('case_')]
    assert 'case_opened' in case_events
    assert 'case_state_transition' in case_events
    assert 'case_note_added' in case_events
    # Newest first, and case rows carry the alert for filtering.
    assert all(row['alert_id'] == alert_id for row in audit
               if row['event_type'].startswith('case_'))

    global_view = client.get('/api/soc/case-audit?limit=10')
    assert global_view.status_code == 200
    rows = global_view.get_json()['audit']
    assert [row['event_type'] for row in rows][:1] == ['case_note_added']
    assert rows[0]['actor'] == 'analyst'
    # Note rows are not transitions; the state change is its own audit row.
    assert rows[0]['from_state'] is None and rows[0]['to_state'] is None


def test_decision_ai_state_honest_when_provider_configured(tmp_path, monkeypatch):
    """With a mock provider configured but no stored AI result, the decision
    explanation must say NOT RUN (provider: mock) — not DISABLED."""
    monkeypatch.setenv('AI_LLM_PROVIDER', 'mock')
    monkeypatch.setenv('DB_FILE', str(tmp_path / 'ai.sqlite'))
    database.init_db(str(tmp_path / 'ai.sqlite'))
    from app import create_app
    application = create_app({
        'DB_FILE': str(tmp_path / 'ai.sqlite'),
        'INGEST_TOKEN': TOKEN,
        'TESTING': True,
        'KNOWLEDGE_DB_FILE': str(tmp_path / 'kb.sqlite'),
    })
    client = application.test_client()
    run = _run_brute_force(client)
    data = soc_report.build_decision_explanation(
        run['alert_ids'][0], db_file=str(tmp_path / 'ai.sqlite'))
    assert data['ai']['status'] == 'disabled'  # stored-data core stays neutral
    response = client.get(f"/api/alerts/{run['alert_ids'][0]}/decision")
    assert response.status_code == 200
    ai = response.get_json()['ai']
    assert ai['status'] == 'not_run'
    assert ai['provider'] == 'mock'
    assert ai['reason'] == 'ai_not_run'


def test_decision_endpoint_404_for_unknown_alert(app_client):
    client, _db = app_client
    response = client.get('/api/alerts/9999/decision')
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Investigation report
# ---------------------------------------------------------------------------

def test_incident_report_contains_all_sections(app_client):
    client, db = app_client
    run = _run_brute_force(client)
    alert_id = run['alert_ids'][0]
    case = _open_case(client, alert_id)
    client.post(f"/api/cases/{case['case_id']}/transition", headers=BEARER,
                json={'to_state': 'confirmed_threat',
                      'note': 'Confirmed by timeline review'})
    response = client.get(f"/api/incidents/{case['incident_id']}/report")
    assert response.status_code == 200
    assert 'text/html' in response.content_type
    body = response.get_data(as_text=True)
    for section in ('Detection', 'Risk', 'Entities', 'Timeline',
                    'Threat intelligence', 'MITRE ATT&amp;CK', 'Jev',
                    'AI investigation', 'Analyst decision', 'SOAR',
                    'Audit trail'):
        assert section in body, section
    # Real stored values, not canned ones.
    assert 'TW-001' in body
    assert 'T1110' in body
    assert '203.0.113.10' in body
    assert 'CONFIRMED_THREAT' in body
    assert 'Confirmed by timeline review' in body
    # Honesty: AI not run and Jev fallback are stated, never claimed.
    assert 'AI not_run' in body
    assert 'fallback' in body
    # Synthetic-environment banner.
    assert 'SYNTHETIC SECURITY VALIDATION ENVIRONMENT' in body


def test_incident_report_404_and_escaping(app_client):
    client, db = app_client
    assert client.get('/api/incidents/INC-zzz/report').status_code == 404
    # Notes are escaped in the report (XSS-safe export).
    run = _run_brute_force(client)
    alert_id = run['alert_ids'][0]
    case = _open_case(client, alert_id)
    client.post(f"/api/cases/{case['case_id']}/notes", headers=BEARER,
                json={'note': '<script>alert(1)</script>'})
    body = client.get(f"/api/incidents/{case['incident_id']}/report") \
        .get_data(as_text=True)
    assert '<script>' not in body
    assert '&lt;script&gt;' in body


# ---------------------------------------------------------------------------
# Reset scope: lab overlays cleared, live cases preserved
# ---------------------------------------------------------------------------

def test_reset_clears_replays_and_lab_cases_but_keeps_live_cases(
        tmp_path):
    db = str(tmp_path / 'reset.sqlite')
    database.init_db(db)
    soc_replay.ensure_replay_schema(db)
    from soar import IncidentService
    run = soc_simulation.create_run('brute_force', db_file=db)
    run = soc_simulation.process_run(run['run_id'], db_file=db)
    # A second, still-generated run drives the replay bookkeeping.
    replay_run = soc_simulation.create_run('port_scan', db_file=db)
    replay = soc_replay.start_replay(replay_run['run_id'], db_file=db)
    lab_case = soc_cases.open_case(
        'INC-labsim', alert_id=run['alert_ids'][0], db_file=db)
    with database.connect(db) as connection:
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details) VALUES "
            "('2025-01-01T00:00:00Z', 'MANUAL', 'LOW', 'manual alert')")
        connection.commit()
        manual_id = connection.execute(
            'SELECT id FROM alerts WHERE rule = ?',
            ('MANUAL',)).fetchone()[0]
    live_incident = IncidentService(db).create_incident(
        'Live incident', severity='low', alert_id=manual_id)
    live_case = soc_cases.open_case(
        live_incident['incident_id'], alert_id=manual_id, db_file=db)
    soc_cases.add_case_note(live_case['case_id'], body='keep me', db_file=db)

    soc_simulation.delete_simulation_data(db_file=db)

    with database.connect(db) as connection:
        assert connection.execute(
            'SELECT COUNT(*) FROM soc_replays').fetchone()[0] == 0
        assert connection.execute(
            'SELECT COUNT(*) FROM soc_replay_events').fetchone()[0] == 0
        remaining = [row['case_id'] for row in connection.execute(
            'SELECT case_id FROM soc_cases')]
    assert lab_case['case_id'] not in remaining
    assert live_case['case_id'] in remaining


# ---------------------------------------------------------------------------
# Console safety: template/JS discipline still holds
# ---------------------------------------------------------------------------

def test_replay_and_case_ui_uses_text_nodes_only():
    script = (PROJECT_ROOT / 'static' / 'dashboard.js').read_text(
        encoding='utf-8')
    for forbidden in ('innerHTML', 'insertAdjacentHTML', 'document.write',
                      'outerHTML'):
        assert forbidden not in script, forbidden
    html = (PROJECT_ROOT / 'templates' / 'dashboard.html').read_text(
        encoding='utf-8')
    assert "id='replay-start'" in html
    assert 'SYNTHETIC / LAB' in html
