"""Phase 5 tests: SOAR engine lifecycle, approvals, idempotency, incidents,
audit integrity, and the AI/execution boundary."""
import json
import sqlite3

import pytest

import database
from actions import ActionError, ActionProvider, default_action_providers
from soar import (AGENT, ApprovalExpiredError, ApprovalNotFoundError,
                  DuplicateExecution, EXECUTION_TRANSITIONS,
                  ExecutionNotFoundError, InvalidStateTransition,
                  PlaybookNotFoundError, SOAREngine, SOARError,
                  USER_ACTOR_RE, _audit, _short_hash)
from playbook import PolicyEngine


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    dbfile = tmp_path / 'soar.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    database.init_db(str(dbfile))
    soar_engine = SOAREngine(db_file=str(dbfile))
    soar_engine.register_built_ins()
    return soar_engine


def seed_alert(db_file, *, rule_id='TW-001', correlation_id='corr-1',
               severity='HIGH'):
    now = database.utc_now()
    with database.connect(db_file) as con:
        con.execute(
            "INSERT INTO alerts (time, rule, severity, details, rule_id, "
            "correlation_id, deterministic_risk_score, risk_band, "
            "jev_priority, jev_status, investigation_status, "
            "mitre_techniques_json, evidence_json, source_event_ids_json) "
            "VALUES (?, 'Brute force', ?, 'synthetic alert', ?, ?, 72, "
            "'high', 'high', 'alert', 'new', '[]', '{}', '[]')",
            (now, severity, rule_id, correlation_id))
        alert_id = con.execute('SELECT MAX(id) FROM alerts').fetchone()[0]
        con.commit()
    return alert_id


def load_alert(db_file, alert_id):
    with database.connect(db_file) as con:
        row = con.execute('SELECT * FROM alerts WHERE id = ?',
                          (alert_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Execution lifecycle
# ---------------------------------------------------------------------------

def test_dry_run_execution_pauses_pending(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    assert execution['state'] == 'PENDING'
    assert execution['dry_run'] is True
    assert execution['evidence']['evidence_id'].startswith('EV-')
    advanced = engine.advance(execution['execution_id'])
    assert advanced['state'] == 'WAITING_APPROVAL'
    actions = engine._execution_actions(execution['execution_id'])
    assert [a['state'] for a in actions] == [
        'PENDING', 'PENDING', 'PENDING', 'WAITING_APPROVAL']


def test_real_execution_runs_to_success_after_approval(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=False)
    assert execution['state'] == 'WAITING_APPROVAL'
    decided = engine.decide_approval(
        engine.list_approvals(decision='pending')[0]['approval_id'],
        'approved', 'analyst.jane', reason='confirmed compromise')
    assert decided['state'] == 'SUCCEEDED'
    actions = engine._execution_actions(execution['execution_id'])
    assert all(a['state'] == 'SUCCEEDED' for a in actions)
    incidents = engine.incident_service.list_incidents()
    assert len(incidents) == 1
    assert incidents[0]['alert_ids'] == [alert['id']]


def test_validation_failure_marks_execution(engine, monkeypatch):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    # Corrupt stored parameters directly to bypass definition-time checks.
    with database.connect(engine.db_file) as con:
        con.execute(
            "UPDATE soar_execution_actions SET parameters_json = ? "
            "WHERE execution_id = ? AND action_index = 2",
            (json.dumps({'title': 12345}), execution['execution_id']))
        con.commit()
    outcome = engine.advance(execution['execution_id'])
    assert outcome['state'] == 'VALIDATION_FAILED'
    assert 'validation_error' in (outcome['error'] or '')


def test_noop_playbook_runs_without_approval(tmp_path, monkeypatch):
    dbfile = str(tmp_path / 'noop.sqlite')
    monkeypatch.setenv('DB_FILE', dbfile)
    database.init_db(dbfile)
    engine = SOAREngine(db_file=dbfile)
    engine.save_playbook({
        'playbook_id': 'TW-PB-020', 'name': 'Noop Flow',
        'description': 'no gates', 'version': 1, 'enabled': True,
        'approval_policy': 'none', 'failure_policy': 'stop',
        'timeout_seconds': 30,
        'retry': {'max_attempts': 1, 'delay_seconds': 0, 'retryable': False},
        'triggers': [{'type': 'alert_created'}],
        'actions': [{'type': 'noop', 'parameters': {}}],
    })
    alert = load_alert(dbfile, seed_alert(dbfile))
    execution = engine.start_execution('TW-PB-020', alert, dry_run=False)
    assert execution['state'] == 'SUCCEEDED'


def test_disabled_playbook_rejected(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    engine.set_playbook_enabled('TW-PB-001', False, actor='admin')
    with pytest.raises(SOARError):
        engine.start_execution('TW-PB-001', alert, dry_run=True)
    engine.set_playbook_enabled('TW-PB-001', True, actor='admin')
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    assert execution['state'] == 'PENDING'


def test_unknown_playbook_raises(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    with pytest.raises(PlaybookNotFoundError):
        engine.start_execution('TW-PB-999', alert, dry_run=True)


def test_trigger_mismatch_rejected(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file,
                                                  rule_id='TW-007'))
    with pytest.raises(SOARError):
        engine.start_execution('TW-PB-001', alert, dry_run=True)


# ---------------------------------------------------------------------------
# Idempotency (5O)
# ---------------------------------------------------------------------------

def test_duplicate_execution_is_rejected(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    first = engine.start_execution('TW-PB-001', alert, dry_run=True)
    with pytest.raises(DuplicateExecution) as excinfo:
        engine.start_execution('TW-PB-001', alert, dry_run=True)
    assert excinfo.value.existing_execution_id == first['execution_id']


def test_idempotency_key_is_deterministic_and_scoped(engine):
    key = engine.idempotency_key('TW-PB-001', 1, 7, 'corr-1')
    assert key == engine.idempotency_key('TW-PB-001', 1, 7, 'corr-1')
    assert key != engine.idempotency_key('TW-PB-001', 2, 7, 'corr-1')
    assert key != engine.idempotency_key('TW-PB-002', 1, 7, 'corr-1')
    assert key != engine.idempotency_key('TW-PB-001', 1, 8, 'corr-1')


def test_different_alerts_get_separate_executions(engine):
    one = load_alert(engine.db_file, seed_alert(engine.db_file,
                                                correlation_id='c1'))
    two = load_alert(engine.db_file, seed_alert(engine.db_file,
                                                correlation_id='c2'))
    ex1 = engine.start_execution('TW-PB-001', one, dry_run=True)
    ex2 = engine.start_execution('TW-PB-001', two, dry_run=True)
    assert ex1['execution_id'] != ex2['execution_id']


# ---------------------------------------------------------------------------
# Approvals (5E)
# ---------------------------------------------------------------------------

def test_rejection_moves_to_terminal_state(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=False)
    engine.advance(execution['execution_id'])
    approval = engine.list_approvals(decision='pending')[0]
    decided = engine.decide_approval(approval['approval_id'], 'rejected',
                                     'analyst.bob', reason='looks benign')
    assert decided['state'] == 'APPROVAL_REJECTED'
    actions = engine._execution_actions(execution['execution_id'])
    gate = next(a for a in actions if a['action_type'] == 'request_approval')
    assert gate['state'] == 'CANCELLED'


def test_double_decision_rejected(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    engine.advance(execution['execution_id'])
    approval = engine.list_approvals(decision='pending')[0]
    engine.decide_approval(approval['approval_id'], 'approved', 'analyst.jane')
    with pytest.raises(InvalidStateTransition):
        engine.decide_approval(approval['approval_id'], 'approved',
                               'analyst.jane')


def test_invalid_decision_value_rejected(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    engine.advance(execution['execution_id'])
    approval = engine.list_approvals(decision='pending')[0]
    with pytest.raises(SOARError):
        engine.decide_approval(approval['approval_id'], 'approved-by-ai',
                               'analyst.jane')
    with pytest.raises(SOARError):
        engine.decide_approval(approval['approval_id'], 'approved', 'bad actor!')


def test_unknown_approval_404_class(engine):
    with pytest.raises(ApprovalNotFoundError):
        engine.decide_approval('APR-NOPE', 'approved', 'analyst.jane')


def test_expired_approval_is_rejected_and_recorded(engine, tmp_path):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    engine.advance(execution['execution_id'])
    approval = engine.list_approvals(decision='pending')[0]
    # Force the TTL into the past, then decide.
    with database.connect(engine.db_file) as con:
        con.execute(
            'UPDATE soar_approvals SET expires_at = ? WHERE approval_id = ?',
            ('2000-01-01T00:00:00.000000Z', approval['approval_id']))
        con.commit()
    with pytest.raises(ApprovalExpiredError):
        engine.decide_approval(approval['approval_id'], 'approved',
                               'analyst.jane')
    with database.connect(engine.db_file) as con:
        row = con.execute(
            'SELECT decision FROM soar_approvals WHERE approval_id = ?',
            (approval['approval_id'],)).fetchone()
    assert row['decision'] == 'expired'
    expired = engine.expire_stale_approvals()
    assert expired == []
    assert engine.get_execution(execution['execution_id'])['state'] == \
        'WAITING_APPROVAL'


def test_expire_stale_approvals_sweep(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    engine.advance(execution['execution_id'])
    with database.connect(engine.db_file) as con:
        con.execute(
            'UPDATE soar_approvals SET expires_at = ? WHERE execution_id = ?',
            ('2000-01-01T00:00:00.000000Z', execution['execution_id']))
        con.commit()
    expired = engine.expire_stale_approvals()
    assert len(expired) == 1
    assert engine.get_execution(execution['execution_id'])['state'] == \
        'APPROVAL_EXPIRED'


# ---------------------------------------------------------------------------
# Cancellation (5P)
# ---------------------------------------------------------------------------

def test_cancel_pending_execution(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    cancelled = engine.cancel_execution(execution['execution_id'],
                                        'analyst.jane', reason='false positive')
    assert cancelled['state'] == 'CANCELLED'
    actions = engine._execution_actions(execution['execution_id'])
    assert all(a['state'] == 'CANCELLED' for a in actions)


def test_cancel_terminal_execution_rejected(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=False)
    engine.decide_approval(
        engine.list_approvals(decision='pending')[0]['approval_id'],
        'rejected', 'analyst.bob')
    with pytest.raises(InvalidStateTransition):
        engine.cancel_execution(execution['execution_id'], 'analyst.jane')


def test_cancel_validates_actor(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    with pytest.raises(SOARError):
        engine.cancel_execution(execution['execution_id'], 'not a valid actor;')
    with pytest.raises(ExecutionNotFoundError):
        engine.cancel_execution('EXE-NOPE', 'analyst.jane')


# ---------------------------------------------------------------------------
# Retry / failure handling (5G)
# ---------------------------------------------------------------------------

class FlakyProvider(ActionProvider):
    action_type = 'notify'
    name = 'flaky'
    description = 'fails once then succeeds'

    def __init__(self):
        self.calls = 0

    def validate(self, parameters):
        pass

    def execute(self, parameters, context, dry_run=True):
        self.calls += 1
        if self.calls == 1:
            raise ActionError('provider_error', 'transient outage')
        return {'action_type': 'notify', 'status': 'succeeded',
                'would_execute': False}


class DeadProvider(ActionProvider):
    action_type = 'notify'
    name = 'dead'
    description = 'always fails'

    def __init__(self):
        self.calls = 0

    def validate(self, parameters):
        pass

    def execute(self, parameters, context, dry_run=True):
        self.calls += 1
        raise ActionError('provider_error', 'permanent outage')


def _engine_with(engine, provider):
    providers = default_action_providers()
    providers['notify'] = provider
    return SOAREngine(db_file=engine.db_file,
                      action_providers=providers,
                      policy_engine=PolicyEngine())


def test_transient_failure_recovers_within_policy_bounds(engine):
    flaky = FlakyProvider()
    retry_engine = _engine_with(engine, flaky)
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = retry_engine.start_execution('TW-PB-001', alert, dry_run=False)
    decided = retry_engine.decide_approval(
        retry_engine.list_approvals(decision='pending')[0]['approval_id'],
        'approved', 'analyst.jane')
    assert decided['state'] == 'SUCCEEDED'
    notify = next(a for a in retry_engine._execution_actions(
        execution['execution_id']) if a['action_type'] == 'notify')
    assert notify['attempts'] == 2
    assert flaky.calls == 2
    failures = [a for a in retry_engine.list_audit(execution['execution_id'])
                if a['event_type'] == 'action_attempt_failed']
    assert len(failures) == 1
    assert failures[0]['failure_reason'].startswith('provider_error:')


def test_permanent_failure_exhausts_retries_and_fails(engine):
    dead = DeadProvider()
    fail_engine = _engine_with(engine, dead)
    alert = load_alert(engine.db_file, seed_alert(engine.db_file,
                                                  correlation_id='c-fail'))
    execution = fail_engine.start_execution('TW-PB-001', alert, dry_run=False)
    decided = fail_engine.decide_approval(
        fail_engine.list_approvals(decision='pending')[0]['approval_id'],
        'approved', 'analyst.jane')
    assert decided['state'] == 'ACTION_FAILED'
    assert dead.calls == 2  # analyst tier caps attempts at 2
    assert 'permanent outage' in decided['error']


def test_non_retryable_category_fails_immediately(engine):
    class Invalid(DeadProvider):
        def execute(self, parameters, context, dry_run=True):
            self.calls += 1
            raise ActionError('validation_error', 'bad parameters')

    provider = Invalid()
    fail_engine = _engine_with(engine, provider)
    alert = load_alert(engine.db_file, seed_alert(engine.db_file,
                                                  correlation_id='c-inv'))
    execution = fail_engine.start_execution('TW-PB-001', alert, dry_run=False)
    fail_engine.decide_approval(
        fail_engine.list_approvals(decision='pending')[0]['approval_id'],
        'approved', 'analyst.jane')
    assert provider.calls == 1
    assert fail_engine.get_execution(execution['execution_id'])['state'] == \
        'ACTION_FAILED'


def test_unexpected_provider_exception_is_contained(engine):
    class Crashing(DeadProvider):
        def execute(self, parameters, context, dry_run=True):
            self.calls += 1
            raise RuntimeError('raw stack trace with api_key=SK-secret-1')

    provider = Crashing()
    fail_engine = _engine_with(engine, provider)
    alert = load_alert(engine.db_file, seed_alert(engine.db_file,
                                                  correlation_id='c-crash'))
    execution = fail_engine.start_execution('TW-PB-001', alert, dry_run=False)
    fail_engine.decide_approval(
        fail_engine.list_approvals(decision='pending')[0]['approval_id'],
        'approved', 'analyst.jane')
    assert fail_engine.get_execution(execution['execution_id'])['state'] == \
        'ACTION_FAILED'
    audit_text = json.dumps(
        fail_engine.list_audit(execution['execution_id']))
    assert 'SK-secret-1' not in audit_text
    assert 'raw stack trace' not in audit_text


# ---------------------------------------------------------------------------
# Incidents (5K)
# ---------------------------------------------------------------------------

def test_incident_creation_and_dedupe(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    first = engine.incident_service.create_incident(
        title='SOAR incident for alert 1', severity='high', alert_id=1,
        correlation_id='corr-1', execution_id='EXE-1')
    assert first['created'] is True
    second = engine.incident_service.create_incident(
        title='SOAR incident for alert 1', severity='high', alert_id=1,
        correlation_id='corr-1', execution_id='EXE-1')
    assert second['created'] is False
    assert second['incident_id'] == first['incident_id']
    incidents = engine.incident_service.list_incidents()
    assert len(incidents) == 1
    assert incidents[0]['alert_ids'] == [1]


def test_incident_validation(engine):
    with pytest.raises(SOARError):
        engine.incident_service.create_incident(title='', severity='high')
    with pytest.raises(SOARError):
        engine.incident_service.create_incident(title='X', severity='zzz')
    with pytest.raises(SOARError):
        engine.incident_service.create_incident(title='X', alert_id='one')


def test_incident_secret_redaction(engine):
    outcome = engine.incident_service.create_incident(
        title='alert api_key=super-secret-value leaked')
    assert 'super-secret-value' not in outcome['incident_id']
    stored = engine.incident_service.get_incident(outcome['incident_id'])
    assert 'super-secret-value' not in json.dumps(stored)


def test_get_incident_missing(engine):
    assert engine.incident_service.get_incident('INC-NOPE') is None


# ---------------------------------------------------------------------------
# Audit integrity (5H)
# ---------------------------------------------------------------------------

def test_every_transition_is_audited(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=False)
    engine.decide_approval(
        engine.list_approvals(decision='pending')[0]['approval_id'],
        'approved', 'analyst.jane')
    audit = engine.list_audit(execution['execution_id'])
    events = [a['event_type'] for a in audit]
    assert 'execution_created' in events
    assert 'state_transition' in events
    assert 'approval_decision' in events
    assert 'incident_created' in events
    assert 'action_succeeded' in events
    # Ordered oldest-first in stored id order via the view (id DESC shown).
    transitions = [(a['from_state'], a['to_state']) for a in audit
                   if a['event_type'] == 'state_transition']
    assert ('PENDING', 'VALIDATING') in transitions
    assert ('VALIDATING', 'WAITING_APPROVAL') in transitions
    assert ('APPROVED', 'RUNNING') in transitions
    assert ('RUNNING', 'SUCCEEDED') in transitions


def test_audit_rows_carry_dry_run_flag(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=True)
    engine.advance(execution['execution_id'])
    audit = engine.list_audit(execution['execution_id'])
    assert all(entry['dry_run'] is True for entry in audit)


def test_playbook_save_and_disable_audited(engine):
    engine.set_playbook_enabled('TW-PB-002', False, actor='admin')
    engine.set_playbook_enabled('TW-PB-002', True, actor='admin')
    audit = [a for a in engine.list_audit()
             if a['event_type'] in ('playbook_enabled', 'playbook_disabled')]
    assert {a['event_type'] for a in audit} == \
        {'playbook_enabled', 'playbook_disabled'}
    assert all(a['actor'] == 'admin' for a in audit)


# ---------------------------------------------------------------------------
# Evidence preservation (5I)
# ---------------------------------------------------------------------------

def test_execution_evidence_snapshot_immutable(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.start_execution('TW-PB-001', alert, dry_run=False)
    before = json.dumps(execution['evidence'], sort_keys=True)
    engine.decide_approval(
        engine.list_approvals(decision='pending')[0]['approval_id'],
        'approved', 'analyst.jane')
    after = json.dumps(
        engine.get_execution(execution['execution_id'])['evidence'],
        sort_keys=True)
    assert before == after
    assert execution['evidence']['jev_decision']['priority'] == 'high'
    assert execution['evidence']['alert']['alert_id'] == alert['id']


# ---------------------------------------------------------------------------
# AI boundary (5M)
# ---------------------------------------------------------------------------

def test_ai_recommendation_is_dry_run_only(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file))
    execution = engine.recommend_execution(
        'TW-PB-001', alert,
        {'recommended_action': 'isolate host ws-1',
         'source': 'ai_investigation'})
    assert execution['dry_run'] is True
    assert execution['state'] == 'PENDING'
    assert execution['context']['actor'] == 'ai-recommendation'
    assert 'isolate host ws-1' in execution['context']['ai_recommendation']
    # And it participates in normal idempotency.
    with pytest.raises(DuplicateExecution):
        engine.recommend_execution('TW-PB-001', alert, {'recommended_action': 'x'})


def test_ai_recommendation_payload_is_bounded(engine):
    alert = load_alert(engine.db_file, seed_alert(engine.db_file,
                                                  correlation_id='c-ai'))
    with pytest.raises(SOARError):
        engine.recommend_execution('TW-PB-001', alert, 42)


def test_actor_pattern_bounds():
    assert USER_ACTOR_RE.match('analyst.jane')
    assert USER_ACTOR_RE.match('ai-recommendation')
    assert not USER_ACTOR_RE.match('bad actor!')
    assert not USER_ACTOR_RE.match('x' * 100)


def test_short_hash_is_stable():
    assert _short_hash('EV', ['a', 1]) == _short_hash('EV', ['a', 1])
    assert _short_hash('EV', ['a', 1]) != _short_hash('EV', ['a', 2])
