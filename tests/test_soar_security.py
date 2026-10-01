"""Phase 5 security tests: injection, untrusted playbook definitions,
secret leakage, oversized payloads, and the AI/execution boundary."""
import json

import pytest

import database
from actions import ActionError, default_action_providers
from playbook import PlaybookValidationError, validate_playbook_definition
from soar import SOAREngine, SOARError, USER_ACTOR_RE


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    dbfile = tmp_path / 'sec.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    database.init_db(str(dbfile))
    soar_engine = SOAREngine(db_file=str(dbfile))
    soar_engine.register_built_ins()
    return soar_engine


def seed_alert(db_file, correlation_id='corr-1'):
    now = database.utc_now()
    with database.connect(db_file) as con:
        con.execute(
            "INSERT INTO alerts (time, rule, severity, details, rule_id, "
            "correlation_id, deterministic_risk_score, risk_band, "
            "jev_priority, jev_status, investigation_status, "
            "mitre_techniques_json, evidence_json, source_event_ids_json) "
            "VALUES (?, 'Brute force', 'HIGH', 'x', 'TW-001', ?, 72, 'high', "
            "'high', 'alert', 'new', '[]', '{}', '[]')",
            (now, correlation_id))
        alert_id = con.execute('SELECT MAX(id) FROM alerts').fetchone()[0]
        con.commit()
    with database.connect(db_file) as con:
        row = con.execute('SELECT * FROM alerts WHERE id = ?',
                          (alert_id,)).fetchone()
    return dict(row)


# ---------------------------------------------------------------------------
# Injection-style playbook definitions (5T)
# ---------------------------------------------------------------------------

def base_definition(**overrides):
    definition = {
        'playbook_id': 'TW-PB-042', 'name': 'Evil', 'description': 'd',
        'version': 1, 'enabled': True, 'approval_policy': 'analyst',
        'failure_policy': 'stop', 'timeout_seconds': 30,
        'retry': {'max_attempts': 1, 'delay_seconds': 0, 'retryable': False},
        'triggers': [{'type': 'alert_created'}],
        'actions': [{'type': 'log', 'parameters': {'message': 'hi'}}],
    }
    definition.update(overrides)
    return definition


@pytest.mark.parametrize('payload', [
    {'type': 'shell', 'parameters': {'command': 'rm -rf /'}},
    {'type': 'sql', 'parameters': {'query': "DELETE FROM alerts; --"}},
    {'type': 'log', 'parameters': {'message': 'ok',
                                   'sql': 'DROP TABLE soar_audit'}},
    {'type': 'http', 'parameters': {'url': 'https://evil.example/exfil'}},
    {'type': 'python', 'parameters': {'code': '__import__("os").system("id")'}},
    {'type': 'host_isolation', 'parameters': {'hostname': 'h',
                                              'endpoint': 'http://x'}},
])
def test_arbitrary_execution_action_types_rejected(payload):
    with pytest.raises(PlaybookValidationError):
        validate_playbook_definition(base_definition(actions=[payload]))


@pytest.mark.parametrize('trigger', [
    {'type': 'expr', 'value': 'alert.rule_id == "TW-001" and __import__("os")'},
    {'type': 'alert_created', 'operator': 'matches',
     'value': '.*; DROP TABLE alerts'},
    {'type': 'rule_id', 'value': "TW-001'; DROP TABLE alerts; --"},
])
def test_injection_triggers_rejected(trigger):
    with pytest.raises(PlaybookValidationError):
        validate_playbook_definition(base_definition(triggers=[trigger]))


def test_playbook_id_and_name_reject_sqlish_payloads():
    with pytest.raises(PlaybookValidationError):
        validate_playbook_definition(base_definition(
            playbook_id="TW-PB-001'; DROP TABLE alerts; --"))
    with pytest.raises(PlaybookValidationError):
        validate_playbook_definition(base_definition(name="Evil\u0000byte"))


def test_action_parameters_with_path_traversal_values_still_bounded(engine):
    # Valid type, hostile value: schema rules decide. The log message is
    # treated as opaque DATA: it is stored redacted/bounded, never executed.
    definition = validate_playbook_definition(base_definition(
        playbook_id='TW-PB-043', name='Pathy',
        actions=[{'type': 'log',
                  'parameters': {'message': '../../etc/passwd; rm -rf /'}}]))
    assert definition['actions'][0]['parameters']['message'].startswith('../../')


# ---------------------------------------------------------------------------
# Secret leakage
# ---------------------------------------------------------------------------

def test_secrets_redacted_in_action_results_and_audit(engine):
    alert = seed_alert(engine.db_file, correlation_id='c-sec')
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    engine.advance(execution['execution_id'])
    approval = engine.list_approvals(decision='pending')[0]
    engine.decide_approval(approval['approval_id'], 'approved', 'analyst.jane',
                           reason='api_key=SK-live-abcdefgh1234 confirm')
    blob = json.dumps(engine.list_audit(execution['execution_id']))
    assert 'SK-live-abcdefgh1234' not in blob


def test_actors_reject_header_like_payloads():
    for hostile in ['Bearer abc', 'x' * 200, 'a;b;c', 'user\nagent: 1']:
        assert not USER_ACTOR_RE.match(hostile)


def test_incident_titles_are_redacted_and_bounded(engine):
    outcome = engine.incident_service.create_incident(
        title='password=hunter2 ' + 'x' * 500)
    stored = engine.incident_service.get_incident(outcome['incident_id'])
    assert 'hunter2' not in json.dumps(stored)
    assert len(stored['title']) <= 200


# ---------------------------------------------------------------------------
# Bounded storage / oversized payloads
# ---------------------------------------------------------------------------

def test_oversized_trigger_payload_bounded(engine):
    alert = seed_alert(engine.db_file, correlation_id='c-big')
    big = {'blob': 'y' * 50000}
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True,
                                       trigger_payload=big)
    payload = execution['trigger']['payload']
    assert payload == {'truncated': True} or len(json.dumps(payload)) < 20000


def test_list_endpoints_capped(engine):
    alert = seed_alert(engine.db_file, correlation_id='c-cap')
    assert len(engine.list_executions(limit=100000)) <= 100
    assert len(engine.list_approvals(limit=100000)) <= 100
    assert len(engine.list_audit(limit=1000000)) <= 100
    assert len(engine.incident_service.list_incidents(limit=999999)) <= 100


# ---------------------------------------------------------------------------
# Future-response adapters fail closed (5L)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('action_type,parameters', [
    ('host_isolation', {'hostname': 'ws1'}),
    ('account_action', {'username': 'alice', 'operation': 'disable'}),
    ('firewall_block', {'ip': '203.0.113.9'}),
    ('send_email', {'subject': 's', 'to': ['soc']}),
    ('create_ticket', {'title': 't'}),
])
def test_no_real_containment_outside_dry_run(action_type, parameters):
    provider = default_action_providers()[action_type]
    with pytest.raises(ActionError) as excinfo:
        provider.execute(parameters, {'execution_id': 'E'}, dry_run=False)
    assert excinfo.value.category == 'not_supported'


@pytest.mark.parametrize('action_type,parameters', [
    ('host_isolation', {'hostname': 'ws 1!'}),
    ('account_action', {'username': 'alice', 'operation': 'nuke'}),
    ('firewall_block', {'ip': 'not an ip at all'}),
    ('send_email', {'subject': 's', 'to': ['http://evil']}),
])
def test_adapter_parameter_validation(action_type, parameters):
    provider = default_action_providers()[action_type]
    with pytest.raises(ActionError):
        provider.validate(parameters)


def test_adapter_dry_run_is_reported_not_executed():
    provider = default_action_providers()['host_isolation']
    result = provider.execute({'hostname': 'ws1'}, {}, dry_run=True)
    assert result['would_execute'] is True
    assert result['status'] == 'would_execute'
    assert 'simulated' in result['expected_effect']


# ---------------------------------------------------------------------------
# AI boundary hard lines (5M)
# ---------------------------------------------------------------------------

def test_ai_recommendation_never_auto_executes(engine):
    alert = seed_alert(engine.db_file, correlation_id='c-ai')
    execution = engine.recommend_execution(
        'TW-PB-001', alert, {'recommended_action': 'isolate ws-1',
                             'confidence': 0.9})
    assert execution['dry_run'] is True
    assert execution['state'] == 'PENDING'
    actions = engine._execution_actions(execution['execution_id'])
    assert all(a['state'] in ('PENDING', 'WAITING_APPROVAL') for a in actions)


def test_ai_recommendation_redacts_secret_payloads(engine):
    alert = seed_alert(engine.db_file, correlation_id='c-ai2')
    execution = engine.recommend_execution(
        'TW-PB-001', alert,
        {'recommended_action': 'x', 'api_key': 'SK-live-zzzz-secret'})
    assert 'SK-live-zzzz-secret' not in json.dumps(execution['context'])
