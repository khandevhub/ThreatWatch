"""Deterministic, explainable risk scoring."""
from detections import DetectionFinding
from risk import (MAX_EVENTS, MAX_HOSTS, MAX_USERS, W_CONFIDENCE, W_FREQUENCY,
                  W_HOSTS, W_INTEL, W_SEVERITY, W_USERS, compute_risk)
from threat_intel import Enrichment


def make_finding(**evidence_overrides):
    evidence = {'source_ip': '1.2.3.4'}
    evidence.update(evidence_overrides)
    return DetectionFinding(
        detection_id='d1', rule_id='TW-004', rule_name='Password Spraying',
        severity='HIGH', confidence=0.75, description='spray',
        event_ids=tuple(f'e{n}' for n in range(1, 11)), evidence=evidence,
        tags=('t',), mitre=('T1110.003',))


def test_perfect_intel_and_users_reach_high_score():
    intel = Enrichment('9.9.9.9', 'ip', True, 0.95, 'test')
    result = compute_risk(make_finding(affected_user_count=5), enrichment=intel,
                          event_count=40)
    assert result.factors['severity'] == W_SEVERITY
    assert result.factors['threat_intel'] == round(W_INTEL * 0.95)
    assert result.factors['affected_users'] == W_USERS
    assert result.factors['frequency'] == W_FREQUENCY
    assert result.factors['confidence'] == round(W_CONFIDENCE * 0.75)
    assert result.score == sum(result.factors.values())
    assert result.band == 'critical'


def test_no_intel_no_users_scores_low():
    result = compute_risk(make_finding(), enrichment=None, event_count=1)
    assert result.factors['threat_intel'] == 0
    assert result.factors['affected_users'] == 0
    assert result.score < 35 and result.band == 'low'


def test_unknown_indicator_contributes_nothing():
    intel = Enrichment('8.8.8.8', 'ip', False, 0.0, 'none')
    result = compute_risk(make_finding(), enrichment=intel)
    assert result.factors['threat_intel'] == 0


def test_explanation_lists_every_factor():
    result = compute_risk(make_finding())
    for factor in ('severity', 'threat_intel', 'affected_users', 'frequency',
                   'affected_hosts', 'confidence'):
        assert factor in result.explanation and factor in result.factors


def test_scores_are_deterministic():
    first = compute_risk(make_finding(affected_user_count=2))
    second = compute_risk(make_finding(affected_user_count=2))
    assert first == second


def test_boundary_saturations():
    intel = Enrichment('9.9.9.9', 'ip', True, 1.0, 'test')
    saturated = compute_risk(
        make_finding(affected_user_count=99, affected_host_count=99),
        enrichment=intel, event_count=999)
    # Weights sum to 100 but the LOW-confidence finding caps the total one
    # point below the theoretical maximum (confidence contribution rounds).
    assert saturated.score >= 95
    assert saturated.factors['affected_users'] == W_USERS
    assert saturated.factors['affected_hosts'] == W_HOSTS
    assert saturated.factors['frequency'] == W_FREQUENCY
    assert saturated.factors['severity'] + saturated.factors['threat_intel'] \
        + saturated.factors['affected_users'] + saturated.factors['frequency'] \
        + saturated.factors['affected_hosts'] == 95

    tiny = compute_risk(make_finding(), enrichment=None, event_count=1)
    assert 0 <= tiny.score <= 100
    low_sev = DetectionFinding(
        detection_id='d2', rule_id='TW-003', rule_name='Traffic Spike',
        severity='LOW', confidence=0.0, description='x', event_ids=('e1',),
        evidence={})
    floor = compute_risk(low_sev, enrichment=None, event_count=1)
    assert floor.score == 9 and floor.band == 'low'


def test_band_boundaries():
    assert compute_risk(
        make_finding(), enrichment=None, event_count=1).band in ('low', 'medium')
    result = compute_risk(make_finding(), enrichment=None,
                          event_count=MAX_EVENTS)
    assert result.band in ('medium', 'high', 'critical')
