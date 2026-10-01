"""SOAR playbook model, trigger evaluation, and policy engine (Phase 5A/5B/5N).

Playbook definitions are data: versioned JSON documents validated against a
strict schema. There are no expressions, no code, and no shell — triggers
are deterministic field comparisons and actions are allowlisted
:class:`actions.ActionProvider` types with schema-validated parameters.

Policy (5N) is a deterministic, closed-vocabulary layer that decides, per
action, whether it is allowed, whether human approval is required, whether
dry-run is mandatory, and the retry/time bounds. Policy can tighten a
playbook but can never loosen it.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re

from actions import ACTION_TYPES, ActionError, default_action_providers

# ---------------------------------------------------------------------------
# Vocabulary and bounds
# ---------------------------------------------------------------------------

#: Ordered severity ladder used by priority-threshold triggers and policy.
SEVERITY_ORDER = ('LOW', 'MEDIUM', 'HIGH')
#: Jev priority ladder (alert priority threshold triggers).
PRIORITY_ORDER = ('low', 'medium', 'high', 'critical')

TRIGGER_TYPES = (
    'alert_created',
    'rule_id',             # e.g. 'TW-001'
    'attack_category',     # Jev attack category, e.g. 'credential_access'
    'priority_at_least',   # Jev priority threshold
    'severity_at_least',   # deterministic severity threshold
    'investigation_status',
    'threat_intel_match',  # alert has >=1 threat-intel match
    'correlation_count_at_least',
)

APPROVAL_POLICIES = ('none', 'analyst', 'administrator')
FAILURE_POLICIES = ('stop', 'continue')
TRIGGER_OPERATORS = ('equals', 'not_equals', 'in', 'not_in')

MAX_ACTIONS = 20
MAX_TRIGGERS = 5
MAX_PARAMS_JSON_CHARS = 4000
MAX_NAME_LEN = 100
MAX_DESC_LEN = 500
MAX_TIMEOUT_SECONDS = 600
MAX_RETRIES = 3
MAX_CORRELATION_THRESHOLD = 1000

_PLAYBOOK_ID_RE = re.compile(r'^TW-PB-[0-9]{3,}$')
_NAME_RE = re.compile(r'^[\w .,:()\-/]{1,' + str(MAX_NAME_LEN) + r'}$')
_RULE_ID_RE = re.compile(r'^TW-[0-9]{3}$')
_CATEGORY_RE = re.compile(r'^[a-z_]{1,40}$')
_STATUS_RE = re.compile(r'^[a-z_]{1,20}$')

DEFAULT_APPROVAL_TTL_MINUTES = 60


class PlaybookValidationError(ValueError):
    """A playbook definition failed strict validation (fail closed)."""


# ---------------------------------------------------------------------------
# Definition validation
# ---------------------------------------------------------------------------

def validate_playbook_definition(definition):
    """Validate an untrusted playbook definition dict; return a normalized copy.

    Raises :class:`PlaybookValidationError` with a bounded, safe message on
    any violation. Never executes, evaluates, or persists anything.
    """
    if not isinstance(definition, dict):
        raise PlaybookValidationError('definition must be a JSON object')
    if len(json.dumps(definition)) > 50000:
        raise PlaybookValidationError('definition exceeds maximum size')

    playbook_id = definition.get('playbook_id')
    if not isinstance(playbook_id, str) or not _PLAYBOOK_ID_RE.match(playbook_id):
        raise PlaybookValidationError(
            "playbook_id must match TW-PB-### (e.g. 'TW-PB-001')")

    name = definition.get('name')
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise PlaybookValidationError(f'name must be 1-{MAX_NAME_LEN} safe characters')

    description = definition.get('description', '')
    if not isinstance(description, str) or len(description) > MAX_DESC_LEN:
        raise PlaybookValidationError(
            f'description must be a string of at most {MAX_DESC_LEN} characters')

    version = definition.get('version')
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise PlaybookValidationError('version must be an integer >= 1')

    enabled = definition.get('enabled', True)
    if not isinstance(enabled, bool):
        raise PlaybookValidationError('enabled must be a boolean')

    approval_policy = definition.get('approval_policy', 'analyst')
    if approval_policy not in APPROVAL_POLICIES:
        raise PlaybookValidationError(
            'approval_policy must be one of ' + str(APPROVAL_POLICIES))

    failure_policy = definition.get('failure_policy', 'stop')
    if failure_policy not in FAILURE_POLICIES:
        raise PlaybookValidationError(
            'failure_policy must be one of ' + str(FAILURE_POLICIES))

    timeout_seconds = definition.get('timeout_seconds', 60)
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) \
            or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise PlaybookValidationError(
            f'timeout_seconds must be an integer in 1..{MAX_TIMEOUT_SECONDS}')

    retry = definition.get('retry', {})
    if not isinstance(retry, dict):
        raise PlaybookValidationError('retry must be an object')
    max_attempts = retry.get('max_attempts', 1)
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) \
            or not 1 <= max_attempts <= MAX_RETRIES + 1:
        raise PlaybookValidationError(
            f'retry.max_attempts must be an integer in 1..{MAX_RETRIES + 1}')
    retry_delay_seconds = retry.get('delay_seconds', 1)
    if not isinstance(retry_delay_seconds, int) or \
            isinstance(retry_delay_seconds, bool) or \
            not 0 <= retry_delay_seconds <= 60:
        raise PlaybookValidationError('retry.delay_seconds must be 0..60')
    retryable = retry.get('retryable', True)
    if not isinstance(retryable, bool):
        raise PlaybookValidationError('retry.retryable must be a boolean')

    triggers = definition.get('triggers')
    if not isinstance(triggers, list) or not triggers:
        raise PlaybookValidationError('triggers must be a non-empty list')
    if len(triggers) > MAX_TRIGGERS:
        raise PlaybookValidationError(
            f'triggers must contain at most {MAX_TRIGGERS} entries')
    normalized_triggers = [_validate_trigger(t) for t in triggers]

    actions = definition.get('actions')
    if not isinstance(actions, list) or not actions:
        raise PlaybookValidationError('actions must be a non-empty list')
    if len(actions) > MAX_ACTIONS:
        raise PlaybookValidationError(
            f'actions must contain at most {MAX_ACTIONS} entries')
    providers = default_action_providers()
    normalized_actions = [_validate_action(i, a, approval_policy, providers)
                          for i, a in enumerate(actions)]

    return {
        'playbook_id': playbook_id,
        'name': name,
        'description': description,
        'version': version,
        'enabled': enabled,
        'approval_policy': approval_policy,
        'failure_policy': failure_policy,
        'timeout_seconds': timeout_seconds,
        'retry': {
            'max_attempts': max_attempts,
            'delay_seconds': retry_delay_seconds,
            'retryable': retryable,
        },
        'triggers': normalized_triggers,
        'actions': normalized_actions,
    }


def _validate_trigger(trigger):
    if not isinstance(trigger, dict):
        raise PlaybookValidationError('each trigger must be an object')
    trigger_type = trigger.get('type')
    if trigger_type not in TRIGGER_TYPES:
        raise PlaybookValidationError(
            'trigger.type must be one of ' + str(TRIGGER_TYPES))
    normalized = {'type': trigger_type}

    if trigger_type in ('rule_id', 'attack_category', 'investigation_status'):
        value = trigger.get('value')
        if not isinstance(value, str) or not value.strip():
            raise PlaybookValidationError(f'trigger {trigger_type} requires a string value')
        if len(value) > 40:
            raise PlaybookValidationError('trigger value exceeds maximum length')
        if trigger_type == 'rule_id' and not _RULE_ID_RE.match(value):
            raise PlaybookValidationError("rule_id must look like 'TW-001'")
        if trigger_type == 'attack_category' and not _CATEGORY_RE.match(value):
            raise PlaybookValidationError('attack_category must be lower_snake_case')
        if trigger_type == 'investigation_status' and not _STATUS_RE.match(value):
            raise PlaybookValidationError('investigation_status must be lower_snake_case')
        normalized['value'] = value
    elif trigger_type in ('priority_at_least', 'severity_at_least'):
        value = trigger.get('value')
        ladder = PRIORITY_ORDER if trigger_type == 'priority_at_least' else SEVERITY_ORDER
        if value not in ladder:
            raise PlaybookValidationError(
                f'trigger {trigger_type} value must be one of ' + str(ladder))
        normalized['value'] = value
    elif trigger_type == 'correlation_count_at_least':
        value = trigger.get('value')
        if not isinstance(value, int) or isinstance(value, bool) or \
                not 1 <= value <= MAX_CORRELATION_THRESHOLD:
            raise PlaybookValidationError(
                'correlation_count_at_least requires an integer in 1..'
                f'{MAX_CORRELATION_THRESHOLD}')
        normalized['value'] = value
    # alert_created / threat_intel_match carry no value.

    operator = trigger.get('operator', 'equals')
    if operator not in TRIGGER_OPERATORS:
        raise PlaybookValidationError(
            'trigger.operator must be one of ' + str(TRIGGER_OPERATORS))
    normalized['operator'] = operator
    return normalized


def _validate_action(index, action, approval_policy, providers=None):
    if not isinstance(action, dict):
        raise PlaybookValidationError(f'action {index} must be an object')
    action_type = action.get('type')
    if action_type not in ACTION_TYPES:
        raise PlaybookValidationError(
            f'action {index}: unknown action type {action_type!r}; '
            'allowed: ' + str(ACTION_TYPES))
    parameters = action.get('parameters', {})
    if not isinstance(parameters, dict):
        raise PlaybookValidationError(f'action {index}: parameters must be an object')
    serialized = json.dumps(parameters)
    if len(serialized) > MAX_PARAMS_JSON_CHARS:
        raise PlaybookValidationError(
            f'action {index}: parameters exceed maximum size')
    # Fail closed at definition time: the action's own provider schema must
    # accept the parameters before the playbook may be stored at all.
    providers = providers if providers is not None else default_action_providers()
    try:
        providers[action_type].validate(parameters)
    except ActionError as exc:
        raise PlaybookValidationError(
            f'action {index}: invalid parameters: {exc.message}') from None
    requires_approval = action.get('requires_approval')
    if requires_approval is not None and not isinstance(requires_approval, bool):
        raise PlaybookValidationError(f'action {index}: requires_approval must be a boolean')
    # Playbooks may volunteer a gate but can never waive the policy one.
    effective_approval = requires_approval if requires_approval else None
    return {
        'type': action_type,
        'parameters': parameters,
        'requires_approval': effective_approval,
        'playbook_approval_policy': approval_policy,
    }


def definition_hash(definition):
    """Stable SHA-256 over the canonical JSON of a (normalized) definition."""
    canonical = json.dumps(definition, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# Trigger evaluation (5B) — deterministic field comparisons only
# ---------------------------------------------------------------------------

def alert_trigger_facts(alert):
    """Extract the bounded fact set triggers may inspect from an alert row."""
    if alert is None:
        return {}
    return {
        'rule_id': alert.get('rule_id'),
        'rule': alert.get('rule'),
        'severity': alert.get('severity'),
        'priority': alert.get('jev_priority'),
        'attack_category': alert.get('jev_attack_category'),
        'investigation_status': alert.get('investigation_status'),
        'threat_intel_match': bool(alert.get('threat_intel_match_count')),
        'correlation_event_count': int(alert.get('correlation_event_count') or 0),
    }


def trigger_matches(trigger, facts):
    """Evaluate one trigger against the alert fact set. Deterministic."""
    trigger_type = trigger['type']
    operator = trigger.get('operator', 'equals')
    value = trigger.get('value')

    if trigger_type == 'alert_created':
        result = True
    elif trigger_type == 'threat_intel_match':
        result = bool(facts.get('threat_intel_match'))
    elif trigger_type == 'rule_id':
        result = facts.get('rule_id') == value
    elif trigger_type == 'attack_category':
        result = facts.get('attack_category') == value
    elif trigger_type == 'investigation_status':
        result = facts.get('investigation_status') == value
    elif trigger_type == 'priority_at_least':
        actual = facts.get('priority')
        result = actual in PRIORITY_ORDER and value in PRIORITY_ORDER and \
            PRIORITY_ORDER.index(actual) >= PRIORITY_ORDER.index(value)
    elif trigger_type == 'severity_at_least':
        actual = facts.get('severity')
        result = actual in SEVERITY_ORDER and value in SEVERITY_ORDER and \
            SEVERITY_ORDER.index(actual) >= SEVERITY_ORDER.index(value)
    elif trigger_type == 'correlation_count_at_least':
        result = facts.get('correlation_event_count', 0) >= int(value)
    else:  # pragma: no cover - validation makes this unreachable
        result = False

    if operator == 'equals':
        return result
    if operator == 'not_equals':
        return not result
    if operator == 'in':
        return result is True
    if operator == 'not_in':
        return result is not True
    return result  # pragma: no cover


def playbook_matches(definition, alert):
    """A playbook fires when ANY of its triggers matches (deterministic OR)."""
    facts = alert_trigger_facts(alert)
    return any(trigger_matches(t, facts) for t in definition['triggers'])


# ---------------------------------------------------------------------------
# Policy engine (5N) — deterministic, configurable, can only tighten
# ---------------------------------------------------------------------------

#: Default policy tiers keyed by the playbook's required approval level.
#: Each tier: max retries, dry-run forcing, and which action types are
#: allowed at all plus which require a human gate regardless of playbook.
DEFAULT_POLICIES = {
    'none': {
        'allowed_action_types': (
            'log', 'collect_evidence', 'notify', 'create_incident',
            'request_approval', 'noop'),
        'approval_required_types': (),
        'force_dry_run': False,
        'max_attempts': 1,
        'max_timeout_seconds': 120,
    },
    'analyst': {
        'allowed_action_types': ACTION_TYPES,
        'approval_required_types': ('host_isolation', 'account_action',
                                    'firewall_block'),
        'force_dry_run': False,
        'max_attempts': 2,
        'max_timeout_seconds': 300,
    },
    'administrator': {
        'allowed_action_types': ACTION_TYPES,
        'approval_required_types': ('host_isolation', 'account_action',
                                    'firewall_block', 'send_email',
                                    'create_ticket'),
        'force_dry_run': False,
        'max_attempts': 3,
        'max_timeout_seconds': 600,
    },
}


class PolicyEngine:
    """Deterministic policy evaluation over validated playbooks.

    The engine consults the policy for the playbook's approval tier and
    combines it with the playbook's own requests. Policy may only make
    execution *more* restrictive: more dry-run, more approvals, fewer
    retries, shorter timeouts, and fewer allowed action types.
    """

    def __init__(self, policies=None):
        self._policies = copy.deepcopy(policies or DEFAULT_POLICIES)

    def policy_for(self, approval_policy):
        policy = self._policies.get(approval_policy)
        if policy is None:
            raise PlaybookValidationError(
                f'no policy configured for approval tier {approval_policy!r}')
        return policy

    def evaluate(self, definition):
        """Return the effective execution plan for a validated definition.

        Result keys: ``allowed``, ``reason``, ``effective_actions`` (list of
        dicts with ``requires_approval`` and ``dry_run`` resolved),
        ``max_attempts``, ``timeout_seconds``, ``force_dry_run``.
        """
        policy = self.policy_for(definition['approval_policy'])
        actions = definition['actions']
        for action in actions:
            if action['type'] not in policy['allowed_action_types']:
                return {
                    'allowed': False,
                    'reason': f"action type {action['type']!r} is not allowed "
                              f"at approval tier {definition['approval_policy']!r}",
                }

        effective = []
        for action in actions:
            gate = action.get('requires_approval')
            if action['type'] in policy['approval_required_types']:
                gate = definition['approval_policy'] or 'analyst'
            effective.append({
                'type': action['type'],
                'parameters': action['parameters'],
                'requires_approval': gate,
                'dry_run': bool(policy['force_dry_run']),
            })

        max_attempts = min(definition['retry']['max_attempts'],
                           policy['max_attempts'])
        timeout = min(definition['timeout_seconds'],
                      policy['max_timeout_seconds'])
        return {
            'allowed': True,
            'reason': None,
            'effective_actions': effective,
            'max_attempts': max_attempts,
            'timeout_seconds': timeout,
            'force_dry_run': bool(policy['force_dry_run']),
            'retry_delay_seconds': definition['retry']['delay_seconds'],
            'retryable': definition['retry']['retryable'],
        }


# ---------------------------------------------------------------------------
# Built-in playbook registry
# ---------------------------------------------------------------------------

def built_in_playbooks():
    """The shipped playbook set. Deterministic and fully dry-run testable."""
    return [
        {
            'playbook_id': 'TW-PB-001',
            'name': 'Brute Force Response',
            'description': ('Response to TW-001 brute-force alerts: snapshot '
                            'evidence, open an incident, and notify analysts. '
                            'Containment requires explicit human approval.'),
            'version': 1,
            'enabled': True,
            'approval_policy': 'analyst',
            'failure_policy': 'stop',
            'timeout_seconds': 60,
            'retry': {'max_attempts': 2, 'delay_seconds': 1, 'retryable': True},
            'triggers': [
                {'type': 'rule_id', 'value': 'TW-001', 'operator': 'equals'},
            ],
            'actions': [
                {'type': 'collect_evidence', 'parameters': {'include_events': True}},
                {'type': 'create_incident',
                 'parameters': {'severity': 'high'}},
                {'type': 'notify',
                 'parameters': {'title': 'Brute force alert',
                                'body': 'ThreatWatch fired TW-001; incident opened.',
                                'recipients': ['soc-analysts']}},
                {'type': 'request_approval', 'parameters': {'scope': 'containment'},
                 'requires_approval': True},
            ],
        },
        {
            'playbook_id': 'TW-PB-002',
            'name': 'Suspicious PowerShell Triage',
            'description': ('Evidence collection and analyst notification for '
                            'suspicious PowerShell detections (TW-005).'),
            'version': 1,
            'enabled': True,
            'approval_policy': 'none',
            'failure_policy': 'continue',
            'timeout_seconds': 60,
            'retry': {'max_attempts': 1, 'delay_seconds': 0, 'retryable': False},
            'triggers': [
                {'type': 'rule_id', 'value': 'TW-005', 'operator': 'equals'},
            ],
            'actions': [
                {'type': 'collect_evidence', 'parameters': {}},
                {'type': 'notify',
                 'parameters': {'title': 'Suspicious PowerShell alert',
                                'recipients': ['soc-analysts']}},
            ],
        },
    ]
