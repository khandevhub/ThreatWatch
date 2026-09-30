"""Jev decision layer: contracts, providers, failures, and fallbacks.

No test here calls the real Jev endpoint; the network provider is exercised
with a local HTTP server and by monkeypatched failures only.
"""
import pytest

import decision
from correlator import Correlator
from decision import (DecisionError, DisabledDecisionProvider,
                      FallbackDecision, JevDecisionProvider,
                      MockDecisionProvider, build_decision_state,
                      get_decision, load_decision_config,
                      make_provider, parse_decision_response)
from detections import DetectionFinding
from risk import compute_risk


def valid_response(**overrides):
    body = {
        'priority': 'high',
        'malicious_likelihood': 0.94,
        'false_positive_likelihood': 0.06,
        'investigation_required': True,
        'attack_category': 'credential_access',
    }
    body.update(overrides)
    return body


# -- configuration -------------------------------------------------------------

def test_jev_disabled_by_default():
    config = load_decision_config({})
    assert config['enabled'] is False
    assert config['model'] == 'jev-1.13-free'
    assert config['api_key'] == ''
    assert isinstance(make_provider(config), DisabledDecisionProvider)


def test_jev_enabled_requires_api_key():
    provider = make_provider(load_decision_config({'JEV_ENABLED': 'true'}))
    assert isinstance(provider, DisabledDecisionProvider)  # fail-safe, not crash
    config = load_decision_config({'JEV_ENABLED': 'true', 'JEV_API_KEY': 'k' * 40})
    assert isinstance(make_provider(config), JevDecisionProvider)


def test_timeout_bounds_enforced():
    with pytest.raises(DecisionError):
        load_decision_config({'JEV_TIMEOUT_SECONDS': '0'})
    with pytest.raises(DecisionError):
        load_decision_config({'JEV_TIMEOUT_SECONDS': '500'})
    assert load_decision_config({'JEV_TIMEOUT_SECONDS': '7.5'})['timeout_seconds'] == 7.5


# -- response validation (untrusted external input) ----------------------------

@pytest.mark.parametrize('payload', [
    None, [], 'decision', 42, {},
    {'priority': 'invalid'},
    {'priority': 'high', 'malicious_likelihood': 1.5},
    {'priority': 'high', 'malicious_likelihood': 'high'},
    {'priority': 'high', 'false_positive_likelihood': -1},
    {'priority': 'high', 'investigation_required': 'yes'},
    {'decision': 'not-an-object'},
])
def test_malformed_responses_are_rejected(payload):
    with pytest.raises(DecisionError):
        parse_decision_response(payload)


def test_out_of_range_likelihoods_rejected_not_clamped():
    with pytest.raises(DecisionError):
        parse_decision_response(valid_response(malicious_likelihood=2))
    with pytest.raises(DecisionError):
        parse_decision_response(valid_response(false_positive_likelihood=-3))


def test_valid_response_and_wrapper_object():
    direct = parse_decision_response(valid_response())
    assert direct['priority'] == 'high'
    assert direct['malicious_likelihood'] == 0.94
    wrapped = parse_decision_response({'decision': valid_response()})
    assert wrapped == direct


def test_unknown_category_is_normalized_to_unknown():
    decision = parse_decision_response(valid_response(attack_category='SOMETHING_ELSE'))
    assert decision['attack_category'] == 'unknown'


# -- mock provider -------------------------------------------------------------

def test_mock_provider_prioritizes_like_an_analyst():
    mock = MockDecisionProvider()
    hot = mock.decide({'deterministic_risk_score': 87, 'known_malicious_ip': True,
                       'affected_users': 4, 'detection': 'password_spraying'})
    assert hot['priority'] == 'high'
    assert hot['investigation_required'] is True
    assert hot['attack_category'] == 'credential_access'
    cold = mock.decide({'deterministic_risk_score': 10, 'known_malicious_ip': False,
                        'affected_users': 0, 'detection': 'traffic_spike'})
    assert cold['priority'] == 'low'


# -- state construction --------------------------------------------------------

def test_decision_state_contains_deterministic_fields():
    finding = DetectionFinding(
        detection_id='d', rule_id='TW-004', rule_name='Password Spraying',
        severity='HIGH', confidence=0.75, description='x', event_ids=('e1', 'e2'),
        evidence={'source_ip': '9.9.9.9'})
    risk = compute_risk(finding)
    group = Correlator().group_findings([finding])[0]
    state = build_decision_state(group, risk)
    assert state['detection'] == 'password_spraying'
    assert state['deterministic_risk_score'] == risk.score
    assert state['event_count'] == 2
    assert 'known_malicious_ip' in state and 'affected_users' in state


# -- failure and fallback ------------------------------------------------------

class ExplodingProvider:
    name = 'exploding'

    def decide(self, state):
        raise DecisionError('simulated timeout')

    def available(self):
        return True


def test_provider_failure_falls_back_and_detection_continues():
    finding = DetectionFinding(
        detection_id='d', rule_id='TW-001', rule_name='Brute Force',
        severity='HIGH', confidence=0.8, description='x', event_ids=('e1',),
        evidence={'source_ip': '1.2.3.4'})
    group = Correlator().group_findings([finding])[0]
    risk = compute_risk(finding)
    outcome = get_decision(ExplodingProvider(), group, risk)
    assert outcome['jev_status'] == 'fallback'
    assert outcome['jev_reason'] == 'provider_unavailable'
    assert outcome['investigation_required'] is True
    assert outcome['priority'] in ('low', 'medium', 'high')


def test_unexpected_provider_error_is_contained():
    class Weird:
        name = 'weird'
        def decide(self, state):
            raise KeyError('boom')
    finding = DetectionFinding(
        detection_id='d', rule_id='TW-001', rule_name='Brute Force',
        severity='LOW', confidence=0.5, description='x', event_ids=('e1',),
        evidence={})
    group = Correlator().group_findings([finding])[0]
    outcome = get_decision(Weird(), group, compute_risk(finding))
    assert outcome['jev_status'] == 'fallback'


def test_disabled_provider_reports_reason():
    outcome = DisabledDecisionProvider().decide({})
    assert outcome['jev_reason'] == 'jev_disabled'
    assert FallbackDecision.decision('x')['investigation_required'] is True


# -- network provider (local server; never the real endpoint) ------------------

def test_jev_provider_parses_local_http_response(monkeypatch):
    class FakeResponse:
        status = 200
        def read(self):
            import json
            return json.dumps(valid_response()).encode('utf-8')
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    captured = {}

    def fake_urlopen(request, timeout):
        captured['authorization'] = request.get_header('Authorization')
        captured['body'] = request.data
        return FakeResponse()

    monkeypatch.setattr(decision.urllib.request, 'urlopen', fake_urlopen)
    provider = JevDecisionProvider({
        'endpoint': 'http://127.0.0.1:1/zen', 'model': 'jev-1.13-free',
        'timeout_seconds': 1, 'api_key': 'test-key-abc',
    })
    outcome = provider.decide({'deterministic_risk_score': 50})
    assert outcome['priority'] == 'high'
    assert captured['authorization'] == 'Bearer test-key-abc'
    assert b'jev-1.13-free' in captured['body']


def test_jev_provider_network_failure_raises_decision_error(monkeypatch):
    def boom(request, timeout):
        raise decision.urllib.error.URLError('connection refused')
    monkeypatch.setattr(decision.urllib.request, 'urlopen', boom)
    provider = JevDecisionProvider({
        'endpoint': 'http://127.0.0.1:1/zen', 'model': 'jev-1.13-free',
        'timeout_seconds': 0.1, 'api_key': 'k' * 40,
    })
    with pytest.raises(DecisionError):
        provider.decide({})


def test_jev_provider_requires_key():
    provider = JevDecisionProvider({
        'endpoint': 'http://127.0.0.1:1/zen', 'model': 'm',
        'timeout_seconds': 1, 'api_key': '',
    })
    assert provider.available() is False
    with pytest.raises(DecisionError):
        provider.decide({})
