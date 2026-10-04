"""SOC operations integration tests.

Covers the simulation lab end-to-end (catalog, generators, run lifecycle,
deterministic validation semantics, mock-AI pass), the SOC console API
(auth, rules, events, alert detail, full validation, demo, reset, incident
promotion), and the static safety contracts for the new console surfaces.
"""
import importlib.util
import json
from pathlib import Path

import pytest

import database
import soc_simulation
from app import _clear_pipeline_state, create_app

TOKEN = 'x' * 32

PROJECT_ROOT = Path(__file__).parents[1]


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    dbfile = tmp_path / 'soc.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    database.init_db(str(dbfile))
    application = create_app({
        'DB_FILE': str(dbfile),
        'INGEST_TOKEN': TOKEN,
        'TESTING': True,
        'KNOWLEDGE_DB_FILE': str(tmp_path / 'kb.sqlite'),
    })
    return application.test_client(), str(dbfile)


def auth():
    return {'Authorization': 'Bearer ' + TOKEN}


# ---------------------------------------------------------------------------
# Scenario catalog and generators
# ---------------------------------------------------------------------------

def test_scenario_catalog_is_complete_and_bounded():
    catalog = soc_simulation.scenario_catalog()
    by_id = {scenario['scenario_id']: scenario for scenario in catalog}
    expected_ids = {
        'brute_force', 'password_spray', 'port_scan', 'suspicious_powershell',
        'suspicious_command', 'suspicious_process', 'privilege_escalation',
        'persistence', 'dns_exfiltration', 'malicious_ip', 'traffic_spike',
        'benign_auth', 'benign_admin_powershell', 'benign_network',
        'mixed_activity',
    }
    assert expected_ids == set(by_id)
    for scenario in catalog:
        assert scenario['name'] and scenario['description']
        assert scenario['classification'] in ('malicious', 'suspicious',
                                              'benign', 'ambiguous')
        assert 1 <= scenario['default_event_count'] \
            <= soc_simulation.MAX_EVENTS_PER_RUN
        expected = scenario['expected']
        assert set(expected) >= {'detection', 'rule_id', 'severity', 'mitre',
                                 'jev_investigation_required'}
        if scenario['classification'] in ('benign', 'ambiguous'):
            assert expected['detection'] is False
        else:
            assert expected['detection'] is True and expected['rule_id']


def test_generators_only_produce_structured_events():
    from datetime import datetime, timezone
    base = datetime.now(timezone.utc)
    for scenario_id in soc_simulation.SCENARIO_GENERATORS:
        events = soc_simulation.generate_events(scenario_id, event_time=base)
        assert 1 <= len(events) <= soc_simulation.MAX_EVENTS_PER_RUN
        for event in events:
            assert event['source'] == soc_simulation.SIM_SOURCE
            assert event['event_type']
            assert event['event_id'].startswith('sim-')
            assert event['event_time'].endswith('Z')


def test_unknown_scenario_rejected():
    with pytest.raises(soc_simulation.SimulationError):
        soc_simulation.generate_events('not-a-scenario')
    with pytest.raises(soc_simulation.SimulationError):
        soc_simulation.create_run('not-a-scenario', db_file=':memory:')


# ---------------------------------------------------------------------------
# Run lifecycle and deterministic validation semantics
# ---------------------------------------------------------------------------

def test_run_lifecycle_process_validate(tmp_path):
    db = str(tmp_path / 'lifecycle.sqlite')
    database.init_db(db)
    run = soc_simulation.create_run('brute_force', db_file=db)
    assert run['status'] == 'generated' and run['event_count'] == 7
    run = soc_simulation.process_run(run['run_id'], db_file=db)
    assert run['status'] == 'processed' and len(run['alert_ids']) == 1
    validation = soc_simulation.validate_run(run['run_id'], db_file=db)
    soc_simulation.store_validation(run['run_id'], validation, db_file=db)
    # AI disabled by default: deterministic checks pass, only 'ai' fails.
    assert validation['outcome'] == 'warning'
    assert validation['failed_checks'] == ['ai']
    alert = validation['actual']['alerts'][0]
    assert alert['rule_id'] == 'TW-001'
    assert alert['severity'] == 'HIGH'
    assert alert['jev_investigation_required'] is True
    assert 'T1110' in alert['mitre']
    assert validation['false_positive'] is False


def test_process_run_is_idempotent(tmp_path):
    db = str(tmp_path / 'idem.sqlite')
    database.init_db(db)
    run = soc_simulation.create_run('port_scan', db_file=db)
    first = soc_simulation.process_run(run['run_id'], db_file=db)
    second = soc_simulation.process_run(run['run_id'], db_file=db)
    assert first['alert_ids'] == second['alert_ids']
    summary = soc_simulation.scenario_summary(db_file=db)
    assert summary['totals']['runs'] == 0  # never validated yet


def test_benign_scenarios_stay_silent(tmp_path):
    db = str(tmp_path / 'benign.sqlite')
    database.init_db(db)
    for scenario_id in ('benign_auth', 'benign_admin_powershell',
                        'benign_network'):
        run = soc_simulation.create_run(scenario_id, db_file=db)
        run = soc_simulation.process_run(run['run_id'], db_file=db)
        validation = soc_simulation.validate_run(run['run_id'], db_file=db)
        assert run['alert_ids'] == []
        assert validation['outcome'] == 'passed', validation['failed_checks']


def test_mixed_activity_is_a_surfaced_false_positive(tmp_path):
    db = str(tmp_path / 'mixed.sqlite')
    database.init_db(db)
    run = soc_simulation.create_run('mixed_activity', db_file=db)
    run = soc_simulation.process_run(run['run_id'], db_file=db)
    validation = soc_simulation.validate_run(run['run_id'], db_file=db)
    assert validation['outcome'] == 'warning'
    assert validation['false_positive'] is True
    assert 'detection' in validation['failed_checks']


def test_mock_ai_turns_detected_scenarios_green(tmp_path, monkeypatch):
    monkeypatch.setenv('AI_LLM_PROVIDER', 'mock')
    monkeypatch.setenv('AI_CACHE_ENABLED', '0')
    from ai_investigation import AIInvestigationEngine
    db = str(tmp_path / 'ai.sqlite')
    knowledge = str(tmp_path / 'kb.sqlite')
    database.init_db(db)
    for scenario_id in ('brute_force', 'dns_exfiltration'):
        _clear_pipeline_state(db)
        run = soc_simulation.create_run(scenario_id, db_file=db)
        run = soc_simulation.process_run(run['run_id'], db_file=db)
        engine = AIInvestigationEngine(db_file=db, knowledge_db_file=knowledge)
        for alert_id in run['alert_ids']:
            result = engine.investigate(alert_id)
            assert result['status'] == 'ok', result
            soc_simulation.persist_ai_result(alert_id, result, db_file=db)
        validation = soc_simulation.validate_run(run['run_id'], db_file=db)
        soc_simulation.store_validation(run['run_id'], validation, db_file=db)
        assert validation['outcome'] == 'passed', validation['failed_checks']
        assert validation['actual']['ai']['available'] >= 1


# ---------------------------------------------------------------------------
# Demo reset scope (simulation data only)
# ---------------------------------------------------------------------------

def test_delete_simulation_data_removes_only_sim_data(tmp_path):
    db = str(tmp_path / 'reset.sqlite')
    database.init_db(db)
    # One non-simulation alert that must survive the reset.
    with database.connect(db) as connection:
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details) "
            "VALUES ('2025-01-01T00:00:00Z', 'BRUTE_FORCE', 'HIGH', 'manual')")
        connection.commit()
    run = soc_simulation.create_run('brute_force', db_file=db)
    run = soc_simulation.process_run(run['run_id'], db_file=db)
    assert run['alert_ids']
    result = soc_simulation.delete_simulation_data(db_file=db)
    assert result == {'simulation_data_removed': True}
    with database.connect(db) as connection:
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 1
        assert connection.execute(
            'SELECT COUNT(*) FROM events').fetchone()[0] == 0
        assert connection.execute(
            'SELECT COUNT(*) FROM simulation_runs').fetchone()[0] == 0
        assert connection.execute(
            'SELECT COUNT(*) FROM simulation_events').fetchone()[0] == 0
        assert connection.execute(
            'SELECT COUNT(*) FROM simulation_run_alerts').fetchone()[0] == 0


def test_reset_demo_tool_dry_run(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / 'tool.sqlite')
    database.init_db(db)
    monkeypatch.setenv('DB_FILE', db)
    spec = importlib.util.spec_from_file_location(
        'reset_demo_tool', PROJECT_ROOT / 'tools' / 'reset_demo.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(['--dry-run']) == 0
    assert 'nothing to reset' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# SOC console API: authentication boundaries
# ---------------------------------------------------------------------------

def test_protected_endpoints_require_bearer(app_client):
    client, _db = app_client
    for method, path in (
            ('POST', '/api/simulation/scenarios/brute_force/generate'),
            ('POST', '/api/simulation/scenarios/brute_force/process'),
            ('POST', '/api/simulation/reset'),
            ('POST', '/api/simulation/validate-all'),
            ('POST', '/api/simulation/demo'),
            ('POST', '/api/soar/executions/EXE-x/advance'),
            ('POST', '/api/alerts/1/incident'),
            ('POST', '/api/alerts/1/ai-question')):
        response = client.open(path, method=method)
        assert response.status_code == 401, (method, path, response.status_code)


def test_wrong_token_rejected(app_client):
    client, _db = app_client
    response = client.post('/api/simulation/reset',
                           headers={'Authorization': 'Bearer ' + 'y' * 32})
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# SOC console API: data endpoints
# ---------------------------------------------------------------------------

def test_rules_endpoint_exposes_thresholds(app_client):
    client, _db = app_client
    response = client.get('/api/rules')
    assert response.status_code == 200
    rules = {rule['rule_id']: rule for rule in response.get_json()['rules']}
    assert len(rules) == 10
    assert rules['TW-001']['threshold'] == 5
    assert rules['TW-001']['window_seconds'] > 0
    assert rules['TW-001']['mitre'] == ['T1110']
    assert rules['TW-004']['code'] == 'PASSWORD_SPRAYING'


def test_events_recent_endpoint(app_client):
    client, db = app_client
    assert client.get('/api/events/recent').get_json()['events'] == []
    run = soc_simulation.create_run('benign_auth', db_file=db)
    soc_simulation.process_run(run['run_id'], db_file=db)
    events = client.get('/api/events/recent?limit=3').get_json()['events']
    assert len(events) == 3
    assert events[0]['source'] == soc_simulation.SIM_SOURCE
    assert 'user_name' in events[0]


def test_generate_process_flow_and_alert_entities(app_client):
    client, db = app_client
    run = client.post('/api/simulation/scenarios/brute_force/generate',
                      headers=auth()).get_json()
    assert run['status'] == 'generated' and run['event_count'] == 7
    data = client.post(
        '/api/simulation/scenarios/brute_force/process',
        headers=auth(), json={'run_id': run['run_id']}).get_json()
    assert data['run']['status'] == 'processed'
    assert data['validation']['failed_checks'] == ['ai']
    alert_id = data['run']['alert_ids'][0]

    queue = client.get('/api/soc/alerts').get_json()
    assert queue[0]['rule_id'] == 'TW-001'
    assert queue[0]['source_ips'] == ['203.0.113.10']
    assert queue[0]['affected_users'] == ['svc-sql']

    detail = client.get(f'/api/soc/alerts/{alert_id}').get_json()
    assert detail['source_ips'] == ['203.0.113.10']
    assert detail['hostnames'] == ['db-lab-01']
    assert 'intel' in detail

    full = client.get(f'/api/soc/alerts/{alert_id}/full').get_json()
    assert full['alert']['id'] == alert_id
    assert 'investigation' in full and 'ai' in full
    assert full['ai']['status'] in ('disabled', 'unavailable', 'ok')
    assert full['soar']['matched_playbooks'] == ['TW-PB-001']
    assert 'audit' in full['soar']


def test_alert_detail_404(app_client):
    client, _db = app_client
    assert client.get('/api/soc/alerts/999').status_code == 404
    assert client.get('/api/soc/alerts/999/full').status_code == 404


def test_run_events_endpoint(app_client):
    client, db = app_client
    run = soc_simulation.create_run('brute_force', db_file=db)
    soc_simulation.process_run(run['run_id'], db_file=db)
    data = client.get(f"/api/simulation/runs/{run['run_id']}/events").get_json()
    assert data['scenario_id'] == 'brute_force'
    assert len(data['events']) == 7
    assert data['alerts'][0]['rule_id'] == 'TW-001'
    assert data['alerts'][0]['source_event_ids']
    assert client.get('/api/simulation/runs/SIMR-does-not-exist/events') \
        .status_code == 404


# ---------------------------------------------------------------------------
# SOC console API: validation, demo, reset, incidents
# ---------------------------------------------------------------------------

def test_validate_all_endpoint_runs_every_scenario(app_client):
    client, _db = app_client
    response = client.post('/api/simulation/validate-all', headers=auth())
    assert response.status_code == 200
    report = response.get_json()
    assert report['totals']['scenarios'] == 15
    assert report['totals']['failed'] == 0
    assert report['totals']['passed'] >= 3
    by_id = {result['scenario_id']: result for result in report['results']}
    assert by_id['brute_force']['outcome'] == 'warning'  # AI off: warning only
    assert by_id['benign_network']['outcome'] == 'passed'
    assert by_id['mixed_activity']['false_positive'] is True
    for result in report['results']:
        assert result['expected'] and 'actual' in result


def test_reset_endpoint_clears_simulation_state(app_client):
    client, db = app_client
    run = soc_simulation.create_run('brute_force', db_file=db)
    soc_simulation.process_run(run['run_id'], db_file=db)
    response = client.post('/api/simulation/reset', headers=auth())
    assert response.status_code == 200
    assert response.get_json() == {'simulation_data_removed': True}
    with database.connect(db) as connection:
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 0
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0


def test_demo_endpoint_full_lifecycle(app_client):
    client, _db = app_client
    response = client.post('/api/simulation/demo', headers=auth())
    assert response.status_code == 200
    demo = response.get_json()
    names = [step['name'] for step in demo['steps']]
    assert names[0] == 'benign_baseline'
    assert 'detection_fired' in names and 'incident_created' in names
    assert len(demo['steps']) == 10
    assert demo['incident_id']
    assert demo['execution_id']
    # TW-PB-001 gates containment behind a human approval.
    assert demo['approval_id']
    # Human approves; dry-run execution then completes (simulated only).
    decision = client.post(
        f"/api/soar/approvals/{demo['approval_id']}/approve",
        headers=auth(), json={'approver': 'analyst'})
    assert decision.status_code == 200
    advanced = client.post(
        f"/api/soar/executions/{demo['execution_id']}/advance",
        headers=auth(), json={'actor': 'analyst'})
    assert advanced.status_code == 200
    assert advanced.get_json()['state'] == 'SUCCEEDED'
    audit = client.get(
        f"/api/soar/executions/{demo['execution_id']}/audit").get_json()
    assert len(audit['audit']) >= 5


def test_incident_promotion_is_deduplicated(app_client):
    client, db = app_client
    run = soc_simulation.create_run('brute_force', db_file=db)
    run = soc_simulation.process_run(run['run_id'], db_file=db)
    alert_id = run['alert_ids'][0]
    first = client.post(f'/api/alerts/{alert_id}/incident', headers=auth(),
                        json={'actor': 'analyst'})
    assert first.status_code == 201
    assert first.get_json()['created'] is True
    second = client.post(f'/api/alerts/{alert_id}/incident', headers=auth(),
                         json={'actor': 'analyst'})
    assert second.status_code == 201
    assert second.get_json()['created'] is False
    assert second.get_json()['incident_id'] == first.get_json()['incident_id']


def test_ai_question_bounds(app_client):
    client, db = app_client
    run = soc_simulation.create_run('brute_force', db_file=db)
    run = soc_simulation.process_run(run['run_id'], db_file=db)
    alert_id = run['alert_ids'][0]
    assert client.post(f'/api/alerts/{alert_id}/ai-question', headers=auth(),
                       json={'question': ''}).status_code == 400
    assert client.post(f'/api/alerts/{alert_id}/ai-question', headers=auth(),
                       json={'question': 'x' * 257}).status_code == 400
    answer = client.post(f'/api/alerts/{alert_id}/ai-question', headers=auth(),
                         json={'question': 'Which source IP is involved?'}
                         ).get_json()
    assert '203.0.113.10' in answer['answer']
    assert answer['sources_checked'] == ['203.0.113.10']


# ---------------------------------------------------------------------------
# Static safety contracts for the new console surfaces
# ---------------------------------------------------------------------------

def test_simulation_source_has_no_execution_or_network_primitives():
    source = (PROJECT_ROOT / 'soc_simulation.py').read_text(encoding='utf-8')
    for forbidden in ('subprocess', 'os.system', 'popen', 'socket.socket',
                      'urlopen', 'requests.', 'paramiko', 'ftplib'):
        assert forbidden not in source, forbidden


def test_dashboard_template_has_no_inline_templated_values():
    html = (PROJECT_ROOT / 'templates' / 'dashboard.html').read_text(
        encoding='utf-8')
    assert '{{' not in html
    assert '<%=' not in html
    assert 'onclick=' not in html


def test_dashboard_console_uses_only_text_nodes():
    script = (PROJECT_ROOT / 'static' / 'dashboard.js').read_text(
        encoding='utf-8')
    for forbidden in ('innerHTML', 'insertAdjacentHTML', 'document.write',
                      'outerHTML'):
        assert forbidden not in script, forbidden
