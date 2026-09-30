"""SOC-core rule registry: metadata, configuration, and enable/disable.

Each detector declares a Rule object (id, name, severity, thresholds, tags,
ATT&CK mapping). Overrides come from configuration values so deployments can
tune thresholds or disable individual rules without code changes. This is an
internal representation that can later be extended toward Sigma-style rule
selections, not a Sigma parser.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Rule:
    """Declarative detection-rule metadata for the modular engine."""

    rule_id: str                      # e.g. 'TW-001'
    name: str                         # e.g. 'Brute Force'
    event_types: tuple                # event types this rule consumes
    code: str = ''                    # stable alert code, e.g. 'BRUTE_FORCE'
    description: str = ''
    severity: str = 'LOW'             # HIGH | MEDIUM | LOW
    threshold: int = 1                # minimum events needed to fire
    window_seconds: int = 0           # 0 = stateless (single-event rule)
    confidence: float = 0.7           # detector's own confidence 0.0-1.0
    tags: tuple = ()
    mitre: tuple = ()                 # ATT&CK technique IDs, e.g. ('T1110.003',)
    enabled: bool = True

    def with_overrides(self, **changes):
        return replace(self, **changes)


SEVERITY_ORDER = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}


def severity_at_least(severity, floor):
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(floor, 99)


class RuleRegistry:
    """Holds rule metadata; load_rules() wires environment overrides."""

    def __init__(self):
        self._rules = {}

    def register(self, rule):
        if rule.rule_id in self._rules:
            raise ValueError(f'duplicate rule_id: {rule.rule_id}')
        self._rules[rule.rule_id] = rule
        return rule

    def get(self, rule_id):
        return self._rules.get(rule_id)

    def all(self):
        return tuple(self._rules.values())

    def enabled_rules(self):
        return tuple(rule for rule in self._rules.values() if rule.enabled)

    def __len__(self):
        return len(self._rules)

    def __iter__(self):
        return iter(self._rules.values())


def _env_flag(environ, name, default=True):
    value = environ.get(name)
    if value is None or value == '':
        return default
    return value.strip().lower() not in ('0', 'false', 'no', 'off')


def _env_int(environ, name, default):
    raw = environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f'{name} must be a positive integer') from None
    if value < 1:
        raise ValueError(f'{name} must be a positive integer')
    return value


def _apply_env_override(environ, rule, field_name, env_suffix):
    """Return rule with an override from RULE_<RULEID>_<SUFFIX>, if present."""
    env_key = f'RULE_{rule.rule_id.replace("-", "_")}_{env_suffix}'
    if env_suffix == 'ENABLED':
        if env_key in environ:
            return rule.with_overrides(enabled=_env_flag(environ, env_key, default=True))
        return rule
    raw = environ.get(env_key)
    if raw is None or raw == '':
        return rule
    if field_name in ('threshold', 'window_seconds'):
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f'{env_key} must be an integer') from None
        if value < 1:
            raise ValueError(f'{env_key} must be a positive integer')
        return rule.with_overrides(**{field_name: value})
    if field_name == 'severity':
        value = raw.strip().upper()
        if value not in SEVERITY_ORDER:
            raise ValueError(f'{env_key} must be one of {tuple(SEVERITY_ORDER)}')
        return rule.with_overrides(severity=value)
    return rule


def load_rules(environ=None):
    """Build the SOC-core registry, applying RULE_* environment overrides."""
    environ = os.environ if environ is None else environ

    # Phase 1 defaults preserved: env names unchanged for the brute-force rule.
    brute_threshold = _env_int(environ, 'BRUTE_FORCE_THRESHOLD', 5)
    brute_window = _env_int(environ, 'DETECTION_WINDOW', 60)

    # Spray threshold = minimum distinct usernames from one source.
    spray_users = _env_int(environ, 'SPRAY_MIN_USERS', 3)
    spray_window = _env_int(environ, 'SPRAY_WINDOW', 300)

    registry = RuleRegistry()

    # -- Phase 1 demo rules, preserved and formalized --------------------------
    registry.register(Rule(
        rule_id='TW-001', name='Brute Force', code='BRUTE_FORCE',
        event_types=('auth_failed',),
        description='Repeated authentication failures from one source against '
                    'one account/service/target within a time window.',
        severity='HIGH', threshold=brute_threshold, window_seconds=brute_window,
        confidence=0.8,
        tags=('authentication', 'credential_access'),
        mitre=('T1110',),
    ))
    registry.register(Rule(
        rule_id='TW-002', name='Port Scan', code='PORT_SCAN',
        event_types=('port_scan',),
        description='Vertical/horizontal port scan reported by a network probe.',
        severity='MEDIUM', threshold=1, window_seconds=0,
        confidence=0.7,
        tags=('reconnaissance', 'network'),
        mitre=('T1046',),
    ))
    registry.register(Rule(
        rule_id='TW-003', name='Traffic Spike', code='TRAFFIC_SPIKE',
        event_types=('traffic_spike',),
        description='High-volume traffic burst reported by a network probe.',
        severity='LOW', threshold=1, window_seconds=0,
        confidence=0.6,
        tags=('network',),
    ))

    # -- SOC-core rules --------------------------------------------------------
    registry.register(Rule(
        rule_id='TW-004', name='Password Spraying', code='PASSWORD_SPRAYING',
        event_types=('auth_failed',),
        description='One source authenticating (and failing) against multiple '
                    'usernames within a short period - distinct from brute force.',
        severity='HIGH', threshold=spray_users,
        window_seconds=spray_window, confidence=0.75,
        tags=('authentication', 'credential_access', 'multi-account'),
        mitre=('T1110.003',),
    ))
    registry.register(Rule(
        rule_id='TW-005', name='Suspicious PowerShell', code='SUSPICIOUS_POWERSHELL',
        event_types=('powershell_script',),
        description='Encoded commands, download cradles, and common abuse flags '
                    'in PowerShell script-block telemetry.',
        severity='HIGH', threshold=1, window_seconds=0,
        confidence=0.8,
        tags=('execution', 'powershell'),
        mitre=('T1059.001', 'T1027'),
    ))
    registry.register(Rule(
        rule_id='TW-006', name='Suspicious Command Line', code='SUSPICIOUS_COMMAND_LINE',
        event_types=('process_start',),
        description='Suspicious command-line indicators on process-start '
                    'events (whoami, adduser,schtasks, curl-pipe-shell, etc.).',
        severity='MEDIUM', threshold=1, window_seconds=0,
        confidence=0.7,
        tags=('execution', 'command_line'),
        mitre=('T1059',),
    ))
    registry.register(Rule(
        rule_id='TW-007', name='Suspicious Process Activity', code='SUSPICIOUS_PROCESS',
        event_types=('process_start',),
        description='Execution of binaries commonly abused for system discovery '
                    'or unauthorized remote access.',
        severity='MEDIUM', threshold=1, window_seconds=0,
        confidence=0.6,
        tags=('execution', 'process'),
        mitre=('T1059.004',),
    ))
    registry.register(Rule(
        rule_id='TW-008', name='Suspicious Privilege Activity', code='SUSPICIOUS_PRIVILEGE',
        event_types=('process_start',),
        description='Privilege-escalation indicators on process-start events '
                    '(sudo/su execution, sudoers modification attempts).',
        severity='HIGH', threshold=1, window_seconds=0,
        confidence=0.65,
        tags=('privilege_escalation', 'process'),
        mitre=('T1548.003', 'T1078.003'),
    ))
    registry.register(Rule(
        rule_id='TW-009', name='Suspicious Persistence Activity', code='SUSPICIOUS_PERSISTENCE',
        event_types=('process_start',),
        description='Persistence indicators on process-start events: cron '
                    'modification and systemd service/timeout installation.',
        severity='HIGH', threshold=1, window_seconds=0,
        confidence=0.65,
        tags=('persistence', 'process'),
        mitre=('T1053.003', 'T1543.002'),
    ))
    registry.register(Rule(
        rule_id='TW-010', name='Possible Data Exfiltration', code='POSSIBLE_EXFILTRATION',
        event_types=('dns_query',),
        description='DNS queries for look-alike internal domains - a possible '
                    'exfiltration or phishing-adjacent indicator.',
        severity='MEDIUM', threshold=1, window_seconds=0,
        confidence=0.4,
        tags=('exfiltration', 'dns'),
        mitre=('T1048.003',),
    ))

    # -- environment overrides (enable/disable, thresholds, severity) ----------
    for rule in list(registry):
        rule = _apply_env_override(environ, rule, 'enabled', 'ENABLED')
        rule = _apply_env_override(environ, rule, 'severity', 'SEVERITY')
        rule = _apply_env_override(environ, rule, 'threshold', 'THRESHOLD')
        rule = _apply_env_override(environ, rule, 'window_seconds', 'WINDOW')
        registry._rules[rule.rule_id] = rule

    return registry


# Additional readable aliases used by detectors and tests.
SEED_RULES_COUNT = 10
