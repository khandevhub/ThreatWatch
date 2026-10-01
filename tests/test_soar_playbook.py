"""Phase 5 tests: playbook definitions, trigger engine, policy, and actions."""
import json

import pytest

from actions import (ACTION_TYPES, ActionError, DisabledNotificationProvider,
                     HostIsolationProvider, LogAction, MockNotificationProvider,
                     NotificationAction, default_action_providers,
                     )
from playbook import (DEFAULT_POLICIES, PlaybookValidationError, PolicyEngine,
                      SEVERITY_ORDER, PRIORITY_ORDER, alert_trigger_facts,
                      alert_trigger_facts as _facts_alias,
                      built_in_playbooks, definition_hash,
                      playbook_matches, validate_playbook_definition)
from soar import (EXECUTION_TRANSITIONS, TERMINAL_STATES,
                  build_execution_evidence, playbook_matches as _pm_alias)

CTX = {'execution_id': 'EXE-X', 'alert_id': 1, 'playbook_id': 'TW-PB-001'}


def base_definition(**overrides):
    definition = {
        'playbook_id': 'TW-PB-010',
        'name': 'Test Playbook',
        'description': 'A test playbook',
        'version': 1,
        'enabled': True,
        'approval_policy': 'analyst',
        'failure_policy': 'stop',
        'timeout_seconds': 60,
        'retry': {'max_attempts': 2, 'delay_seconds': 1, 'retryable': True},
        'triggers': [{'type': 'alert_created'}],
        'actions': [
            {'type': 'log', 'parameters': {'message': 'hello'}},
        ],
    }
    definition.update(overrides)
    return definition


def alert_row(**overrides):
    row = {
        'id': 1, 'rule_id': 'TW-001', 'rule': 'Brute force', 'severity': 'HIGH',
        'jev_priority': 'high', 'jev_attack_category': 'credential_access',
        'investigation_status': 'new', 'threat_intel_match_count': 1,
        'correlation_event_count': 6,
    }
    row.update(overrides)
    return row


# ---------------------------------------------------------------------------
# Playbook validation
# ---------------------------------------------------------------------------

def test_built_in_playbooks_validate():
    normalized = [validate_playbook_definition(d) for d in built_in_playbooks()]
    assert {d['playbook_id'] for d in normalized} == {'TW-PB-001', 'TW-PB-002'}
    brute = normalized[0]
    assert brute['actions'][0]['type'] == 'collect_evidence'
    assert brute['triggers'][0]['value'] == 'TW-001'


@pytest.mark.parametrize('mutate', [
    lambda d: d.pop('playbook_id'),
    lambda d: d.update(playbook_id='PB-1'),
    lambda d: d.update(playbook_id='TW-PB-0001; DROP TABLE alerts'),
    lambda d: d.update(name=''),
    lambda d: d.update(version=0),
    lambda d: d.update(version=True),
    lambda d: d.update(enabled='yes'),
    lambda d: d.update(approval_policy='auto'),
    lambda d: d.update(failure_policy='ignore'),
    lambda d: d.update(timeout_seconds=100000),
    lambda d: d.update(retry={'max_attempts': 99}),
    lambda d: d.update(triggers=[]),
    lambda d: d.update(actions=[]),
    lambda d: d.update(triggers=[{'type': 'python_expr', 'value': 'os'}]),
    lambda d: d.update(triggers=[{'type': 'rule_id', 'value': 'TW-1'}]),
    lambda d: d.update(triggers=[{'type': 'priority_at_least', 'value': 'MAXIMUM'}]),
    lambda d: d.update(triggers=[{'type': 'correlation_count_at_least', 'value': 0}]),
    lambda d: d.update(actions=[{'type': 'shell', 'parameters': {'cmd': 'whoami'}}]),
    lambda d: d.update(actions=[{'type': 'log', 'parameters': {'cmd': 'whoami'}}]),
    lambda d: d.update(actions=[{'type': 'log',
                                 'parameters': {'message': 'x' * 501}}]),
    lambda d: d.update(actions=[{'type': 'host_isolation',
                                 'parameters': {'hostname': 'ws 1'}}]),
    lambda d: d.update(actions=[{'type': 'notify',
                                 'parameters': {'title': 'T', 'body': 9}}]),
])
def test_malformed_definitions_rejected(mutate):
    definition = base_definition()
    mutate(definition)
    with pytest.raises(PlaybookValidationError):
        validate_playbook_definition(definition)


def test_definition_hash_is_stable_and_covers_content():
    first = validate_playbook_definition(base_definition())
    second = validate_playbook_definition(base_definition())
    assert definition_hash(first) == definition_hash(second)
    changed = validate_playbook_definition(base_definition(version=2))
    assert definition_hash(changed) != definition_hash(first)


def test_oversized_definition_rejected():
    definition = base_definition()
    definition['description'] = 'x' * 60000
    with pytest.raises(PlaybookValidationError):
        validate_playbook_definition(definition)


# ---------------------------------------------------------------------------
# Trigger engine (5B)
# ---------------------------------------------------------------------------

def test_trigger_facts_are_bounded():
    facts = alert_trigger_facts(alert_row())
    assert set(facts) == {
        'rule_id', 'rule', 'severity', 'priority', 'attack_category',
        'investigation_status', 'threat_intel_match',
        'correlation_event_count'}


def test_rule_id_trigger_matching():
    definition = validate_playbook_definition(base_definition(
        triggers=[{'type': 'rule_id', 'value': 'TW-001'}]))
    assert playbook_matches(definition, alert_row())
    assert not playbook_matches(definition, alert_row(rule_id='TW-002'))
    assert not playbook_matches(definition, None)


def test_priority_and_severity_thresholds():
    severity_trigger = validate_playbook_definition(base_definition(
        triggers=[{'type': 'severity_at_least', 'value': 'MEDIUM'}]))
    assert playbook_matches(severity_trigger, alert_row(severity='HIGH'))
    assert not playbook_matches(severity_trigger, alert_row(severity='LOW'))
    priority_trigger = validate_playbook_definition(base_definition(
        triggers=[{'type': 'priority_at_least', 'value': 'critical'}]))
    assert playbook_matches(priority_trigger, alert_row(jev_priority='critical'))
    assert not playbook_matches(priority_trigger, alert_row(jev_priority='low'))


def test_intel_and_correlation_triggers():
    intel = validate_playbook_definition(base_definition(
        triggers=[{'type': 'threat_intel_match'}]))
    assert playbook_matches(intel, alert_row(threat_intel_match_count=1))
    assert not playbook_matches(intel, alert_row(threat_intel_match_count=0))
    corr = validate_playbook_definition(base_definition(
        triggers=[{'type': 'correlation_count_at_least', 'value': 5}]))
    assert playbook_matches(corr, alert_row(correlation_event_count=6))
    assert not playbook_matches(corr, alert_row(correlation_event_count=3))


def test_investigation_status_trigger():
    definition = validate_playbook_definition(base_definition(
        triggers=[{'type': 'investigation_status', 'value': 'resolved'}]))
    assert playbook_matches(definition,
                            alert_row(investigation_status='resolved'))
    assert not playbook_matches(definition, alert_row())


# ---------------------------------------------------------------------------
# Policy engine (5N)
# ---------------------------------------------------------------------------

def test_none_tier_forbids_sensitive_actions():
    definition = validate_playbook_definition(base_definition(
        approval_policy='none',
        actions=[{'type': 'host_isolation',
                  'parameters': {'hostname': 'ws1'}}]))
    plan = PolicyEngine().evaluate(definition)
    assert not plan['allowed']


def test_sensitive_actions_gain_mandatory_gate():
    definition = validate_playbook_definition(base_definition(
        approval_policy='analyst',
        actions=[{'type': 'host_isolation',
                  'parameters': {'hostname': 'ws1'}}]))
    plan = PolicyEngine().evaluate(definition)
    assert plan['allowed']
    assert plan['effective_actions'][0]['requires_approval'] == 'analyst'


def test_policy_only_tightens_bounds():
    definition = validate_playbook_definition(base_definition(
        retry={'max_attempts': 4, 'delay_seconds': 1, 'retryable': True},
        timeout_seconds=600))
    plan = PolicyEngine().evaluate(definition)
    assert plan['max_attempts'] == 2          # analyst tier cap
    assert plan['timeout_seconds'] == 300     # tier cap, not playbook's 600


def test_administrator_tier_gate_map():
    definition = validate_playbook_definition(base_definition(
        approval_policy='administrator',
        actions=[{'type': 'send_email',
                  'parameters': {'subject': 'Report', 'to': ['soc']}}]))
    plan = PolicyEngine().evaluate(definition)
    assert plan['effective_actions'][0]['requires_approval'] == 'administrator'


# ---------------------------------------------------------------------------
# Action framework (5C/5J/5L)
# ---------------------------------------------------------------------------

def test_provider_registry_matches_allowlist():
    providers = default_action_providers()
    assert set(providers) == set(ACTION_TYPES)


def test_log_action_redacts_and_bounds():
    result = LogAction().execute(
        {'message': 'password=hunter2 and more'}, CTX, dry_run=False)
    assert result['status'] == 'succeeded'
    assert 'hunter2' not in json.dumps(result)


def test_notification_action_sanitizes_and_records():
    provider = MockNotificationProvider()
    action = NotificationAction(provider)
    result = action.execute(
        {'title': 'Alert', 'body': 'token Bearer abc.def',
         'recipients': ['soc-analysts']},
        CTX, dry_run=False)
    assert result['status'] == 'succeeded'
    assert 'abc.def' not in json.dumps(result)
    assert len(provider.sent) == 1


def test_notification_recipients_reject_urls():
    action = NotificationAction(MockNotificationProvider())
    with pytest.raises(ActionError):
        action.validate({'title': 'T', 'recipients': ['https://evil']})
    with pytest.raises(ActionError):
        action.validate({'title': 'T', 'recipients': ['a' * 500]})


def test_dry_run_changes_nothing_external():
    provider = MockNotificationProvider()
    result = NotificationAction(provider).execute(
        {'title': 'Alert'}, CTX, dry_run=True)
    assert result['would_execute'] is True
    assert provider.sent == []


def test_disabled_notification_provider_marks_suppressed():
    result = DisabledNotificationProvider().send(
        'T', 'B', ['soc'], dry_run=False, context={})
    assert result['suppressed'] is True


def test_host_isolation_fails_closed_outside_dry_run():
    with pytest.raises(ActionError) as excinfo:
        HostIsolationProvider().execute({'hostname': 'ws1'}, CTX, dry_run=False)
    assert excinfo.value.category == 'not_supported'


def test_host_isolation_dry_run_reports_expected_effect():
    result = HostIsolationProvider().execute({'hostname': 'ws1'}, CTX,
                                             dry_run=True)
    assert result['status'] == 'would_execute'
    assert 'expected_effect' in result


def test_unknown_action_parameters_rejected():
    for action_type, parameters in [
        ('log', {'message': 'ok', 'cmd': 'whoami'}),
        ('noop', {'anything': 1}),
        ('collect_evidence', {'path': '/etc/passwd'}),
        ('host_isolation', {'hostname': 'bad hostname!', 'extra': 1}),
    ]:
        provider = default_action_providers()[action_type]
        with pytest.raises(ActionError):
            provider.validate(parameters)


def test_action_error_categories_are_closed():
    from actions import ERROR_CATEGORIES
    assert set(ERROR_CATEGORIES) == {
        'validation_error', 'provider_error', 'not_supported', 'timeout',
        'cancelled'}


def test_action_error_rejects_unknown_category():
    with pytest.raises(ValueError):
        ActionError('explode_everything', 'nope')


def test_action_error_message_redacted_and_bounded():
    error = ActionError('provider_error',
                        'failed with api_key=SK-live-abcdef123456 ' + 'x' * 500)
    assert 'SK-live' not in error.message
    assert len(error.message) <= 300


# ---------------------------------------------------------------------------
# Evidence preservation (5I)
# ---------------------------------------------------------------------------

def test_evidence_snapshot_shape_and_redaction():
    package = {
        'alert': {'id': 3, 'details': 'token Bearer abc.def.ghi', 'rule': 'R'},
        'risk': {'score': 70, 'band': 'high', 'factors': {}, 'explanation': ''},
        'evidence': {'entities': {'usernames': ['alice']}},
        'timeline': {'total_events': 1, 'truncated': False,
                     'entries': [{'timestamp': 't', 'event_type': 'auth'}]},
        'threat_intel': {'matches': [], 'unavailable': []},
        'mitre': {'techniques': [], 'unavailable': []},
        'related_alerts': {'alerts': [], 'unavailable': []},
    }
    evidence = build_execution_evidence(package, 'EXE-1', dry_run=True)
    assert evidence['evidence_id'].startswith('EV-')
    assert evidence['alert_id'] == 3
    assert evidence['jev_decision']['priority'] is None
    assert 'abc.def' not in json.dumps(evidence)
    assert evidence['timeline']['total_events'] == 1
    assert evidence['playbook_execution_id'] == 'EXE-1'


def test_evidence_deterministic_per_execution():
    package = {'alert': {'id': 1}, 'risk': None, 'evidence': None,
               'timeline': None, 'threat_intel': None, 'mitre': None,
               'related_alerts': None}
    one = build_execution_evidence(package, 'EXE-1', dry_run=True)
    two = build_execution_evidence(package, 'EXE-1', dry_run=True)
    one['captured_at'] = two['captured_at'] = ''
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


# ---------------------------------------------------------------------------
# State machine vocabulary
# ---------------------------------------------------------------------------

def test_terminal_states_have_no_outgoing_transitions():
    for state in TERMINAL_STATES:
        assert EXECUTION_TRANSITIONS[state] == set()


def test_transition_map_covers_all_states():
    assert set(EXECUTION_TRANSITIONS) == {
        'PENDING', 'VALIDATING', 'WAITING_APPROVAL', 'APPROVED', 'RUNNING',
        'SUCCEEDED', 'VALIDATION_FAILED', 'APPROVAL_REJECTED',
        'APPROVAL_EXPIRED', 'ACTION_FAILED', 'CANCELLED', 'TIMED_OUT'}
