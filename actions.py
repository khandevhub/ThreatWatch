"""SOAR action framework (Phase 5C/5J/5L).

Every executable SOAR action is a small, isolated provider behind one
interface. The playbook engine never contains provider-specific logic; it
only calls :meth:`ActionProvider.validate` / :meth:`ActionProvider.execute`
and records the structured result.

Safety properties:

- **Allowlisted action types.** ``ACTION_TYPES`` is the closed set the engine
  accepts; a playbook referencing anything else fails validation.
- **No arbitrary execution.** No action runs shell commands, SQL, URLs, or
  code. Parameters are schema-validated before execution.
- **Dry-run first.** Every provider implements an explicit dry-run path that
  returns ``would_execute``/``expected_effect`` and changes nothing.
- **Sanitized results.** Results are JSON-safe dicts; errors are mapped to
  bounded error categories so raw exceptions never leak into the audit log.
- **No real destructive integrations.** The future-response adapters
  (host isolation, account action, firewall, email, ticketing) ship as
  mock/disabled providers only. Real containment is out of scope for this
  phase.
"""
from __future__ import annotations

import re

from evidence import redact_text

try:  # Python 3.11+
    from typing import NotRequired, TypedDict
except ImportError:  # pragma: no cover - fallback for older interpreters
    TypedDict = dict  # type: ignore[assignment]
    NotRequired = object  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Error categories
# ---------------------------------------------------------------------------

#: Closed set of error categories recorded in execution/audit rows. Raw
#: exception text is never persisted; providers map failures into one of
#: these categories plus a redacted, length-bounded message.
ERROR_CATEGORIES = (
    'validation_error',      # parameters failed schema validation
    'provider_error',        # the provider raised an unexpected error
    'not_supported',         # provider cannot serve this action
    'timeout',               # action exceeded its deadline
    'cancelled',             # cancelled before completion
)


class ActionError(Exception):
    """A controlled action failure with a bounded, safe error category."""

    def __init__(self, category, message):
        allowed = ERROR_CATEGORIES
        if category not in allowed:
            raise ValueError(f'unknown error category: {category!r}')
        super().__init__(message)
        self.category = category
        # Never persist raw exception chains; keep one redacted line.
        self.message = redact_text(str(message))[:300]


# ---------------------------------------------------------------------------
# Parameter validation helpers (bounded, typed, allowlisted)
# ---------------------------------------------------------------------------

_MAX_STR = 500
_MAX_LIST = 20
_TITLE_RE = re.compile(r'^[\w .,:()\-/]{1,200}$')
_ID_RE = re.compile(r'^[\w.\-:#]{1,120}$')
_SEVERITIES = ('low', 'medium', 'high', 'critical')


def _require_str(params, key, *, allow_empty=False, max_len=_MAX_STR,
                 pattern=None):
    value = params.get(key)
    if not isinstance(value, str):
        raise ActionError('validation_error', f'{key} must be a string')
    if not allow_empty and not value.strip():
        raise ActionError('validation_error', f'{key} must not be empty')
    if len(value) > max_len:
        raise ActionError('validation_error', f'{key} exceeds maximum length')
    if pattern is not None and not pattern.match(value):
        raise ActionError('validation_error', f'{key} has invalid format')
    return value


def _optional_str(params, key, *, max_len=_MAX_STR):
    value = params.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ActionError('validation_error', f'{key} must be a string or null')
    if len(value) > max_len:
        raise ActionError('validation_error', f'{key} exceeds maximum length')
    return value


def _str_list(params, key, *, max_items=_MAX_LIST, max_len=_MAX_STR):
    value = params.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or \
            any(not isinstance(item, str) for item in value):
        raise ActionError('validation_error', f'{key} must be a list of strings')
    if len(value) > max_items:
        raise ActionError('validation_error', f'{key} exceeds maximum items')
    return [item[:max_len] for item in value]


def _reject_unknown(params, allowed):
    """Fail closed on any parameter key outside the explicit allowlist."""
    unknown = set(params) - set(allowed)
    if unknown:
        raise ActionError('validation_error',
                          f'unknown parameters: {sorted(unknown)}')


# ---------------------------------------------------------------------------
# ActionProvider interface
# ---------------------------------------------------------------------------

class ActionProvider:
    """Base class for SOAR action providers.

    Subclasses declare an ``action_type`` (the allowlisted string used in
    playbook definitions) and implement :meth:`validate` (pure schema check)
    and :meth:`execute` (the bounded effect, honoring ``dry_run``).
    """

    action_type = None
    name = None
    description = None

    def describe(self):
        """Bounded provider descriptor safe to expose via the API."""
        return {
            'action_type': self.action_type,
            'name': self.name,
            'description': self.description,
        }

    def validate(self, parameters):
        """Raise :class:`ActionError` when parameters are invalid."""
        raise NotImplementedError

    def execute(self, parameters, context, dry_run=True):
        """Run the action.

        ``context`` carries execution metadata (execution_id, alert_id,
        playbook_id, evidence snapshot). Implementations MUST honor
        ``dry_run`` and return a JSON-serializable dict containing at least
        ``status`` ('succeeded'|'would_execute') and ``action_type``.
        """
        raise NotImplementedError


class LogAction(ActionProvider):
    """Record a structured, sanitized note on the execution."""

    action_type = 'log'
    name = 'Log message'
    description = ('Records a sanitized analyst note on the playbook '
                   'execution. No external effect.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'message'})
        _require_str(parameters, 'message', max_len=500)

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        message = redact_text(parameters['message'])[:500]
        return {
            'action_type': self.action_type,
            'status': 'would_execute' if dry_run else 'succeeded',
            'would_execute': bool(dry_run),
            'message': message,
        }


class EvidenceCollectionAction(ActionProvider):
    """Snapshot the alert's investigation package as immutable evidence.

    The evidence bundle is produced by the SOAR engine (see
    ``soar.build_execution_evidence``) before actions run; this action
    records which snapshot was taken so response steps can reference it.
    """

    action_type = 'collect_evidence'
    name = 'Collect evidence snapshot'
    description = ('Persists an immutable snapshot of the alert, events, '
                   'timeline, risk decision, and threat intel before any '
                   'response action.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'include_events'})
        include = parameters.get('include_events')
        if include is not None and not isinstance(include, bool):
            raise ActionError('validation_error',
                              'include_events must be a boolean')

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        snapshot_present = bool(context.get('evidence'))
        return {
            'action_type': self.action_type,
            'status': 'would_execute' if dry_run else 'succeeded',
            'would_execute': bool(dry_run),
            'evidence_snapshot_id': context.get('evidence_id'),
            'snapshot_present': snapshot_present,
            'expected_effect': 'attach immutable evidence snapshot',
        }


class NotificationAction(ActionProvider):
    """Send a sanitized notification through a NotificationProvider."""

    action_type = 'notify'
    name = 'Notify analyst'
    description = ('Sends a sanitized notification (title + bounded body) '
                   'through the configured notification provider.')

    def __init__(self, notification_provider):
        self.notification_provider = notification_provider

    def validate(self, parameters):
        _reject_unknown(parameters, {'title', 'body', 'recipients'})
        _require_str(parameters, 'title', max_len=200, pattern=_TITLE_RE)
        _optional_str(parameters, 'body', max_len=1000)
        recipients = _str_list(parameters, 'recipients', max_items=10)
        for recipient in recipients:
            # Recipients are logical channel names, never URLs or addresses
            # that could be dereferenced: strict identifier charset only.
            if not _ID_RE.match(recipient):
                raise ActionError('validation_error',
                                  'recipients must be logical identifiers')

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        title = redact_text(parameters['title'])[:200]
        body = redact_text(parameters.get('body') or '')[:1000]
        recipients = parameters.get('recipients') or ['soc-analysts']
        return self.notification_provider.send(
            title=title, body=body, recipients=recipients,
            dry_run=dry_run, context={
                'execution_id': context.get('execution_id'),
                'alert_id': context.get('alert_id'),
                'playbook_id': context.get('playbook_id'),
            })


class IncidentAction(ActionProvider):
    """Create (or dedupe) an incident record for the triggering alert."""

    action_type = 'create_incident'
    name = 'Create incident record'
    description = ('Creates a deterministic incident linked to the alert, '
                   'evidence, and execution; duplicate alerts reuse the '
                   'existing incident.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'title', 'severity'})
        title = parameters.get('title')
        if title is not None:
            _require_str(parameters, 'title', max_len=200, pattern=_TITLE_RE)
        severity = parameters.get('severity')
        if severity is not None and severity not in _SEVERITIES:
            raise ActionError('validation_error',
                              'severity must be one of ' + str(_SEVERITIES))

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        if dry_run:
            return {
                'action_type': self.action_type,
                'status': 'would_execute',
                'would_execute': True,
                'expected_effect': 'create or reuse incident for alert',
            }
        incident_service = context.get('incident_service')
        if incident_service is None:
            raise ActionError('provider_error', 'incident service unavailable')
        title = redact_text(parameters.get('title') or
                            f"SOAR incident for alert {context.get('alert_id')}")
        return incident_service.create_incident(
            title=title[:200],
            severity=parameters.get('severity') or 'medium',
            alert_id=context.get('alert_id'),
            correlation_id=context.get('correlation_id'),
            execution_id=context.get('execution_id'))


class ApprovalAction(ActionProvider):
    """Marker action declaring that human approval is required to proceed.

    The engine enforces the gate (an approval row must reach ``approved``
    before later actions run); this action itself only records the request.
    """

    action_type = 'request_approval'
    name = 'Request approval gate'
    description = ('Marks a human approval gate; the engine pauses until an '
                   'authorized analyst or administrator decides. AI output '
                   'can never satisfy this gate.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'scope'})
        scope = parameters.get('scope')
        if scope is not None and scope not in ('containment', 'remediation'):
            raise ActionError('validation_error',
                              "scope must be 'containment' or 'remediation'")

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        return {
            'action_type': self.action_type,
            'status': 'would_execute' if dry_run else 'succeeded',
            'would_execute': bool(dry_run),
            'approval_gate': parameters.get('scope') or 'containment',
        }


class NoOpAction(ActionProvider):
    """Deliberate no-operation, useful for templates and tests."""

    action_type = 'noop'
    name = 'No operation'
    description = 'Does nothing; records a successful structured result.'

    def validate(self, parameters):
        _reject_unknown(parameters, set())

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        return {
            'action_type': self.action_type,
            'status': 'would_execute' if dry_run else 'succeeded',
            'would_execute': bool(dry_run),
        }


# ---------------------------------------------------------------------------
# Response-adapter interfaces (5L) — interfaces only in this phase
# ---------------------------------------------------------------------------

class HostIsolationProvider(ActionProvider):
    """Interface for future host-isolation integrations.

    Ships disabled by default. A real integration must be a new provider
    registered deliberately; the shipped mock only simulates.
    """

    action_type = 'host_isolation'
    name = 'Host isolation (mock)'
    description = ('FUTURE/NOT REAL: simulates isolating a host. No real '
                   'isolation is performed in this phase.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'hostname', 'reason'})
        _require_str(parameters, 'hostname', max_len=120, pattern=_ID_RE)
        _optional_str(parameters, 'reason', max_len=300)

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        if dry_run:
            return {
                'action_type': self.action_type,
                'status': 'would_execute',
                'would_execute': True,
                'hostname': parameters['hostname'],
                'expected_effect': 'isolate host (simulated only in this phase)',
            }
        # Fail closed: no mock mutation outside dry-run, so nothing in this
        # phase can ever change a real host.
        raise ActionError('not_supported',
                          'real host isolation is not enabled in this phase')


class AccountActionProvider(ActionProvider):
    """Interface for future account containment (disable/suspend)."""

    action_type = 'account_action'
    name = 'Account action (mock)'
    description = ('FUTURE/NOT REAL: simulates disabling or suspending an '
                   'account. No real account change is performed.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'username', 'operation', 'reason'})
        _require_str(parameters, 'username', max_len=120, pattern=_ID_RE)
        operation = parameters.get('operation', 'disable')
        if operation not in ('disable', 'suspend'):
            raise ActionError('validation_error',
                              "operation must be 'disable' or 'suspend'")
        _optional_str(parameters, 'reason', max_len=300)

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        if dry_run:
            return {
                'action_type': self.action_type,
                'status': 'would_execute',
                'would_execute': True,
                'username': parameters['username'],
                'operation': parameters.get('operation', 'disable'),
                'expected_effect':
                    f"{parameters.get('operation', 'disable')} account "
                    '(simulated only in this phase)',
            }
        raise ActionError('not_supported',
                          'real account actions are not enabled in this phase')


class FirewallProvider(ActionProvider):
    """Interface for future firewall block/allow changes."""

    action_type = 'firewall_block'
    name = 'Firewall block (mock)'
    description = ('FUTURE/NOT REAL: simulates blocking an IP. No firewall '
                   'is modified in this phase.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'ip', 'direction'})
        ip = parameters.get('ip')
        if not isinstance(ip, str) or not _ID_RE.match(ip):
            raise ActionError('validation_error', 'ip must be a plain address string')
        _optional_str(parameters, 'direction', max_len=20)

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        if dry_run:
            return {
                'action_type': self.action_type,
                'status': 'would_execute',
                'would_execute': True,
                'ip': parameters['ip'],
                'expected_effect': 'block IP (simulated only in this phase)',
            }
        raise ActionError('not_supported',
                          'real firewall changes are not enabled in this phase')


class EmailProvider(ActionProvider):
    """Interface for future email integrations (distinct from notify)."""

    action_type = 'send_email'
    name = 'Send email (mock)'
    description = ('FUTURE/NOT REAL: simulates sending an email. Requires a '
                   'future real provider to do anything.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'subject', 'body', 'to'})
        _require_str(parameters, 'subject', max_len=200, pattern=_TITLE_RE)
        _optional_str(parameters, 'body', max_len=1000)
        for to in _str_list(parameters, 'to', max_items=10):
            if not _ID_RE.match(to):
                raise ActionError('validation_error',
                                  'to must be logical identifiers')

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        if dry_run:
            return {
                'action_type': self.action_type,
                'status': 'would_execute',
                'would_execute': True,
                'subject': redact_text(parameters['subject'])[:200],
                'expected_effect': 'send email (simulated only in this phase)',
            }
        raise ActionError('not_supported',
                          'real email delivery is not enabled in this phase')


class TicketingProvider(ActionProvider):
    """Interface for future ticketing integrations."""

    action_type = 'create_ticket'
    name = 'Create ticket (mock)'
    description = ('FUTURE/NOT REAL: simulates creating a ticket in an '
                   'external system.')

    def validate(self, parameters):
        _reject_unknown(parameters, {'title', 'description'})
        _require_str(parameters, 'title', max_len=200, pattern=_TITLE_RE)
        _optional_str(parameters, 'description', max_len=1000)

    def execute(self, parameters, context, dry_run=True):
        self.validate(parameters)
        if dry_run:
            return {
                'action_type': self.action_type,
                'status': 'would_execute',
                'would_execute': True,
                'title': redact_text(parameters['title'])[:200],
                'expected_effect': 'create external ticket (simulated)',
            }
        raise ActionError('not_supported',
                          'real ticketing is not enabled in this phase')


# ---------------------------------------------------------------------------
# Notification providers (5J)
# ---------------------------------------------------------------------------

class NotificationProvider:
    """Base notification provider interface."""

    name = None

    def send(self, title, body, recipients, dry_run=True, context=None):
        raise NotImplementedError


class MockNotificationProvider(NotificationProvider):
    """In-memory notification sink for tests and local development."""

    name = 'mock'

    def __init__(self, max_history=256):
        self.max_history = max(1, min(int(max_history), 1024))
        self.sent = []

    def send(self, title, body, recipients, dry_run=True, context=None):
        record = {
            'action_type': 'notify',
            'status': 'would_execute' if dry_run else 'succeeded',
            'would_execute': bool(dry_run),
            'provider': self.name,
            'title': redact_text(str(title))[:200],
            'body': redact_text(str(body or ''))[:1000],
            'recipients': list(recipients)[:10],
            'execution_id': (context or {}).get('execution_id'),
            'alert_id': (context or {}).get('alert_id'),
        }
        if not dry_run:
            self.sent.append(record)
            if len(self.sent) > self.max_history:
                self.sent.pop(0)
        return record


class DisabledNotificationProvider(NotificationProvider):
    """Fail-soft sink: notifications are recorded as suppressed."""

    name = 'disabled'

    def send(self, title, body, recipients, dry_run=True, context=None):
        return {
            'action_type': 'notify',
            'status': 'would_execute' if dry_run else 'succeeded',
            'would_execute': bool(dry_run),
            'provider': self.name,
            'suppressed': True,
            'title': redact_text(str(title))[:200],
            'recipients': list(recipients)[:10],
        }


# ---------------------------------------------------------------------------
# Registries / factories
# ---------------------------------------------------------------------------

#: Closed allowlist of action types the playbook engine accepts.
ACTION_TYPES = (
    'log', 'collect_evidence', 'notify', 'create_incident',
    'request_approval', 'noop', 'host_isolation', 'account_action',
    'firewall_block', 'send_email', 'create_ticket',
)


def default_action_providers(notification_provider=None):
    """Build the standard provider mapping used by the SOAR engine.

    Sensitive future-response adapters (host isolation, account action,
    firewall, email, ticketing) are included as mock/dry-run-only
    implementations: outside dry-run they raise ``not_supported`` rather
    than perform any real effect.
    """
    notification_provider = notification_provider or MockNotificationProvider()
    providers = [
        LogAction(),
        EvidenceCollectionAction(),
        NotificationAction(notification_provider),
        IncidentAction(),
        ApprovalAction(),
        NoOpAction(),
        HostIsolationProvider(),
        AccountActionProvider(),
        FirewallProvider(),
        EmailProvider(),
        TicketingProvider(),
    ]
    return {provider.action_type: provider for provider in providers}
