"""Jev structured-decision layer (advisory only).

ThreatWatch depends on the DecisionProvider interface, never on HTTP
directly. JevDecisionProvider calls the OpenCode Zen System One endpoint;
MockDecisionProvider is deterministic and used by tests. Jev failure,
timeout, malformed responses, or disabled configuration never break event
ingestion or deterministic detection — the provider returns a fallback
decision instead.

Jev is an advisory structured-decision layer. It is NOT the primary
detection engine and cannot execute security actions.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger('threatwatch.decision')

JEV_ENDPOINT_DEFAULT = 'https://opencode.ai/zen/v1/systemone'
JEV_MODEL_DEFAULT = 'jev-1.13-free'
JEV_TIMEOUT_DEFAULT = 10

PRIORITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
VALID_PRIORITIES = tuple(PRIORITY_ORDER)
VALID_CATEGORIES = (
    'credential_access', 'execution', 'persistence', 'privilege_escalation',
    'discovery', 'lateral_movement', 'exfiltration', 'command_and_control',
    'reconnaissance', 'impact', 'unknown',
)
ALLOWED_KEYS = ('priority', 'malicious_likelihood', 'false_positive_likelihood',
                'investigation_required', 'attack_category')


class DecisionError(RuntimeError):
    """The decision provider could not produce a usable decision."""


def load_decision_config(environ=None):
    """Read JEV_* configuration; never logs or stores the API key."""
    environ = os.environ if environ is None else environ
    enabled_raw = (environ.get('JEV_ENABLED') or '').strip().lower()
    enabled = enabled_raw in ('1', 'true', 'yes', 'on')
    timeout_raw = environ.get('JEV_TIMEOUT_SECONDS', str(JEV_TIMEOUT_DEFAULT))
    try:
        timeout = float(timeout_raw)
    except ValueError:
        raise DecisionError('JEV_TIMEOUT_SECONDS must be a number') from None
    if not 0 < timeout <= 120:
        raise DecisionError('JEV_TIMEOUT_SECONDS must be between 0 and 120')
    api_key = environ.get('JEV_API_KEY') or ''
    return {
        'enabled': enabled,
        'model': environ.get('JEV_MODEL', JEV_MODEL_DEFAULT),
        'timeout_seconds': timeout,
        'api_key': api_key,
        'endpoint': environ.get('JEV_ENDPOINT', JEV_ENDPOINT_DEFAULT),
    }


def build_decision_state(group, risk, enrichment=None):
    """Build the compact structured state payload for one decision request."""
    state = {
        'event_count': len(group.event_ids),
        'time_window_minutes': 5,
        'known_malicious_ip': bool(enrichment and enrichment.known_malicious
                                   and enrichment.indicator_type == 'ip'),
        'threat_intel_confidence': (enrichment.confidence
                                    if enrichment and enrichment.known_malicious else 0.0),
        'affected_users': group.evidence.get('affected_user_count', 0),
        'detection': group.rule_name.lower().replace(' ', '_'),
        'rule_id': group.rule_id,
        'severity': group.severity,
        'deterministic_risk_score': risk.score,
        'mitre': list(group.mitre),
    }
    return state


def parse_decision_response(payload):
    """Validate and normalize one provider response; raise DecisionError on junk.

    The external response is treated as untrusted input: only whitelisted
    keys and bounded, type-checked values are accepted.
    """
    if not isinstance(payload, dict):
        raise DecisionError('decision response must be a JSON object')
    body = payload.get('decision', payload)
    if not isinstance(body, dict):
        raise DecisionError('decision body must be a JSON object')

    priority = body.get('priority')
    if not isinstance(priority, str) or priority.lower() not in VALID_PRIORITIES:
        raise DecisionError('missing or invalid priority')

    def _likelihood(key, default=0.5):
        value = body.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise DecisionError(f'{key} must be a number')
        value = float(value)
        if not 0.0 <= value <= 1.0:
            raise DecisionError(f'{key} out of range')
        return value

    malicious = _likelihood('malicious_likelihood')
    false_positive = _likelihood('false_positive_likelihood')

    investigation = body.get('investigation_required', True)
    if not isinstance(investigation, bool):
        raise DecisionError('investigation_required must be a boolean')

    category = body.get('attack_category', 'unknown')
    if not isinstance(category, str) or category.lower() not in VALID_CATEGORIES:
        category = 'unknown'
    category = category.lower()

    priority = priority.lower()
    return {
        'priority': priority,
        'malicious_likelihood': malicious,
        'false_positive_likelihood': false_positive,
        'investigation_required': investigation,
        'attack_category': category,
    }


class DecisionProvider:
    """Interface: submit structured state, receive a bounded decision."""

    name = 'abstract'

    def decide(self, state):
        raise NotImplementedError

    def available(self):
        return True


class MockDecisionProvider(DecisionProvider):
    """Deterministic, offline provider for tests and Jev-free operation."""

    name = 'mock'

    def decide(self, state):
        score = state.get('deterministic_risk_score', 0)
        known = bool(state.get('known_malicious_ip'))
        users = state.get('affected_users', 0)
        if known and score >= 70 or users >= 3 and score >= 60:
            priority = 'high'
        elif score >= 45:
            priority = 'medium'
        else:
            priority = 'low'
        category = 'credential_access' if 'auth' in str(state.get('detection', '')) \
            or 'brute' in str(state.get('detection', '')) \
            or 'spraying' in str(state.get('detection', '')) else 'execution'
        return {
            'priority': priority,
            'malicious_likelihood': round(min(1.0, score / 100 + (0.2 if known else 0)), 2),
            'false_positive_likelihood': round(max(0.0, 0.4 - score / 250), 2),
            'investigation_required': priority in ('high', 'medium') or known,
            'attack_category': category,
        }


class JevDecisionProvider(DecisionProvider):
    """Calls the OpenCode Zen System One endpoint; fails safe on any error."""

    name = 'jev'

    def __init__(self, config):
        self.endpoint = config['endpoint']
        self.model = config['model']
        self.timeout = config['timeout_seconds']
        self.api_key = config['api_key']  # kept out of logs on purpose

    def available(self):
        return bool(self.api_key)

    def decide(self, state):
        if not self.api_key:
            raise DecisionError('JEV_API_KEY is not configured')
        questions = {
            'priority': 'alert priority (critical|high|medium|low)',
            'malicious_likelihood': 'malicious likelihood (0.0-1.0)',
            'false_positive_likelihood': 'false-positive likelihood (0.0-1.0)',
            'investigation_required': 'investigation required (true|false)',
            'attack_category': ('attack category (credential_access|execution|'
                                'persistence|privilege_escalation|discovery|'
                                'lateral_movement|exfiltration|command_and_control|'
                                'reconnaissance|impact|unknown)'),
        }
        body = {
            'model': self.model,
            'input': (
                'You are the Jev decision layer inside a SOC. Given the '
                'structured alert state below, answer with ONLY a JSON object '
                'with exactly these keys: ' + ', '.join(
                    f'"{key}" ({desc})' for key, desc in questions.items()) + '. '
                'No explanations.'
            ),
            'structured_state': state,
            'questions': list(questions.keys()),
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(body).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'Bearer ' + self.api_key,
            },
            method='POST',
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise DecisionError(f'Jev endpoint returned {response.status}')
                payload = json.loads(response.read().decode('utf-8'))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            # Never leak the Authorization header or key material in logs.
            logger.warning('Jev decision unavailable (%s); using fallback',
                           type(exc).__name__)
            raise DecisionError('Jev request failed') from None
        return parse_decision_response(payload)


class FallbackDecision:
    """The safe decision used when Jev is disabled or unavailable."""

    @staticmethod
    def decision(reason):
        return {
            'priority': 'medium',
            'malicious_likelihood': None,
            'false_positive_likelihood': None,
            'investigation_required': True,
            'attack_category': 'unknown',
            'jev_status': 'fallback',
            'jev_reason': reason,
        }


def make_provider(config):
    """Return the configured provider (disabled -> always-fallback provider)."""
    if not config['enabled']:
        return DisabledDecisionProvider()
    if not config['api_key']:
        logger.warning('JEV_ENABLED is true but JEV_API_KEY is not set; '
                       'Jev decisions are disabled for this run')
        return DisabledDecisionProvider()
    return JevDecisionProvider(config)


class DisabledDecisionProvider(DecisionProvider):
    """Used when JEV_ENABLED=false: always returns the safe fallback."""

    name = 'disabled'

    def available(self):
        return False

    def decide(self, state):
        return FallbackDecision.decision('jev_disabled')


def get_decision(provider, group, risk, enrichment=None):
    """One-stop helper: try provider, fall back safely on any failure."""
    state = build_decision_state(group, risk, enrichment)
    try:
        decision = provider.decide(state)
        if decision.get('jev_status') == 'fallback':
            # Already a safe fallback (e.g. Jev disabled): do not re-validate;
            # its None likelihood fields are intentionally unparseable.
            return decision
        decision = parse_decision_response(decision)
        decision['jev_status'] = 'ok'
        decision['jev_reason'] = provider.name
        return decision
    except DecisionError:
        logger.info('Decision provider failed; deterministic pipeline continues')
        # Keep the reason generic: provider error text is untrusted input.
        fallback = FallbackDecision.decision('provider_unavailable')
        fallback['jev_status'] = 'fallback'
        return fallback
    except Exception as exc:  # never let the decision layer break detection
        logger.warning('Unexpected decision-layer error (%s); continuing', type(exc).__name__)
        return FallbackDecision.decision('provider_error')
