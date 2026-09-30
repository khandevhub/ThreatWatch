"""Modular detection engine for the SOC core.

Rules are independently testable and individually disableable. Single-event
rules run pure pattern matchers; windowed rules (brute force, password
spraying) evaluate accumulated per-key state over a time window. Every
finding carries structured evidence so correlation, risk scoring, and the
decision layer can explain themselves.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import re
import uuid

from event_model import SecurityEvent
from rules import Rule

logger = logging.getLogger('threatwatch.detections')

# Evidence keys reused across rules; keep them stable for tests/UI.
EV_SOURCE_IP = 'source_ip'
EV_USER = 'username'
EV_HOST = 'hostname'
EV_PROCESS = 'process_name'
EV_COMMAND_LINE = 'command_line'
EV_USER_COUNT = 'affected_user_count'
EV_ATTEMPT_COUNT = 'attempt_count'
EV_USERS = 'affected_users'
EV_PORTS = 'targeted_ports'
EV_BYTES = 'bytes'
EV_DOMAIN = 'domain'
EV_EVENT_IDS = 'event_ids'


@dataclass(frozen=True)
class DetectionFinding:
    """Structured output of one rule firing."""

    detection_id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    description: str
    event_ids: tuple
    evidence: dict
    tags: tuple = ()
    mitre: tuple = ()
    primary_event_id: str | None = None

    def to_dict(self):
        return {
            'detection_id': self.detection_id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'event_ids': list(self.event_ids),
            'evidence': self.evidence,
            'tags': list(self.tags),
            'mitre': list(self.mitre),
            'primary_event_id': self.primary_event_id or (
                self.event_ids[-1] if self.event_ids else None),
        }


class DetectionError(ValueError):
    """Internal error while evaluating a rule (never user-facing)."""


def _new_detection_id():
    return str(uuid.uuid4())


def _matches(pattern, text):
    """re.search with pre-compiled patterns; text must be a string."""
    return pattern.search(text) is not None


_B64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
_URL_RE = re.compile(r'https?://[^\s\'"]+')
_IWR_RE = re.compile(
    r'(?i)\b(iwr|iex|invoke-expression|invoke-webrequest|invoke-restmethod|'
    r'downloadstring|downloadfile)\b')
_DOWN_CRADLE_RE = re.compile(
    r'(?i)((iwr|iex|invoke-webrequest|invoke-restmethod|downloadstring)'
    r'[^;|]{0,80}https?://|https?://[^;|]{0,80}'
    r'(iex|invoke-expression|downloadstring))')
_PS_FLAG_RE = re.compile(r'(?i)-enc(?:odedcommand)?\b|-w\b\s*(hidden|1)\b'
                         r'|-nop\b|-noni\b|-windowstyle\s+hidden\b')
_ABUSE_RE = re.compile(
    r'(?i)(\bbash\s+-i\b|/dev/tcp/|\bnc\b\s+-e\b|\bncat\b\s+(-e|--exec)\b|'
    r'chmod\s+777\b|curl[^|]{0,120}\|\s*(ba)?sh\b|wget[^|]{0,120}\|\s*(ba)?sh\b)')
_SUSPICIOUS_BINARY_RE = re.compile(
    r'(?i)(^|[\\/])(nc|ncat|netcat|socat|nmap|hydra|john|hashcat)(\.exe)?$')
_PRIV_SUDO_RE = re.compile(r'(?i)(^|[\\/])(sudo|su|doas|pkexec)(\.exe)?$')
_PRIV_ESCALATION_RE = re.compile(
    r'(?i)(/etc/sudoers|sudoers\.d|chmod\s+[0-7]{0,2}[46]44\s+/etc/(passwd|shadow)|'
    r'usermod\s+[^;]{0,80}-aG\s+(sudo|wheel|admin)|'
    r'net\s+localgroup\s+administrators\s+[^;]{0,80}/add)')
_CRED_DUMP_RE = re.compile(r'(?i)\b(mimikatz|secretsdump|lazagne|procdump\b)')
_PERSIST_CRON_RE = re.compile(
    r'(?i)(^|[\s/])crontab\s+(-l|-e|-r|-)|/etc/cron(\.d|\.daily|\.hourly)?/')
_PERSIST_SERVICE_RE = re.compile(
    r'(?i)systemctl\s+(enable|start)\b|/etc/systemd/system/[^;]{0,120}\.service|'
    r'systemd-run\b')
_EXFIL_LIKE_DOMAIN_RE = re.compile(
    r'(?i)^([\w-]+\.)?'
    r'(corp|internal|intranet|finance|hr|mail|git|jenkins|vpn)'
    r'[-.]?(corp|internal|local|company|corpnet)?'
    r'\.(com|net|org|io|dev|co|biz|info)$')


class DetectionEngine:
    """Runs enabled rules against normalized events.

    Stateless rules evaluate one event at a time. Windowed rules (brute
    force, password spraying) are delegated to a ``windowed_state`` evaluator
    that owns per-source counters (see detector.WindowedAuthState).
    """

    def __init__(self, registry, intel=None):
        self.registry = registry
        self.intel = intel

    def evaluate_event(self, event, windowed_state=None):
        """Evaluate all enabled rules for one event; returns [DetectionFinding]."""
        findings = []
        enabled = {rule.rule_id for rule in self.registry.enabled_rules()}

        if event.event_type == 'auth_failed' and windowed_state is not None:
            findings.extend(windowed_state.evaluate(event))

        matchers = {
            'powershell_script': self._match_powershell,
            'process_start': self._match_process_start,
            'dns_query': self._match_dns,
            'port_scan': self._match_port_scan,
            'traffic_spike': self._match_traffic_spike,
        }
        matcher = matchers.get(event.event_type)
        if matcher:
            findings.extend(matcher(event, enabled))
        return findings

    # -- stateless matchers ----------------------------------------------------

    def _match_powershell(self, event, enabled):
        if 'TW-005' not in enabled:
            return []
        command = (event.command_line or '') or str(event.metadata.get('message') or '')
        if not command:
            return []
        hits = []
        if _matches(_PS_FLAG_RE, command) or _matches(_B64_RE, command):
            hits.append('encoded_command_or_flags')
        if _matches(_DOWN_CRADLE_RE, command):
            hits.append('download_cradle')
        if _matches(_IWR_RE, command) and _matches(_URL_RE, command):
            hits.append('remote_content_execution')
        if not hits:
            return []
        return [self._finding(
            event, self.registry.get('TW-005'),
            'Suspicious PowerShell: ' + ', '.join(sorted(set(hits))),
            {EV_COMMAND_LINE: command[:512],
             EV_HOST: event.host or 'unknown',
             'indicators': sorted(set(hits))},
        )]

    def _match_process_start(self, event, enabled):
        command = (event.command_line or '') or str(event.metadata.get('message') or '')
        process_name = (event.process or '').strip()
        base = process_name.rsplit('/', 1)[-1].rsplit('\\', 1)[-1].lower()
        host = event.host or 'unknown'
        findings = []

        if 'TW-006' in enabled and command:
            hits = []
            if _matches(_ABUSE_RE, command):
                hits.append('abuse_pattern')
            if command.strip().lower().startswith('curl') and '|' in command \
                    and re.search(r'\b(ba)?sh\b', command.lower()):
                hits.append('curl_pipe_shell')
            if re.search(r'(?i)\b(useradd|adduser)\b', command) \
                    or re.search(r'(?i)\bnet\s+user\b[^;]{0,80}/add\b', command):
                hits.append('account_creation')
            if re.search(r'(?i)\bschtasks\s+/create\b', command) \
                    or re.search(r'(?i)\breg\s+(add|query)\b[^;]{0,80}(run|policies)\b', command):
                hits.append('scheduled_task_or_registry_persistence')
            if re.search(r'(?i)\b(wevtutil\s+cl|clear-eventlog)\b', command):
                hits.append('log_clearing')
            if _matches(_CRED_DUMP_RE, command):
                hits.append('credential_dumping_tool')
            if hits:
                findings.append(self._finding(
                    event, self.registry.get('TW-006'),
                    'Suspicious command line: ' + ', '.join(sorted(set(hits))),
                    {EV_COMMAND_LINE: command[:512],
                     EV_HOST: host,
                     EV_PROCESS: process_name or None,
                     'indicators': sorted(set(hits))},
                ))

        if 'TW-007' in enabled and base and _matches(_SUSPICIOUS_BINARY_RE, base):
            findings.append(self._finding(
                event, self.registry.get('TW-007'),
                f'Suspicious process execution: {base}',
                {EV_PROCESS: process_name or base,
                 EV_HOST: host,
                 EV_COMMAND_LINE: command[:512] or None},
            ))

        if 'TW-008' in enabled:
            priv_hits = []
            if base and _matches(_PRIV_SUDO_RE, base):
                priv_hits.append('sudo_like_execution')
            if command and _matches(_PRIV_ESCALATION_RE, command):
                priv_hits.append('privilege_escalation_command')
            if priv_hits:
                findings.append(self._finding(
                    event, self.registry.get('TW-008'),
                    'Suspicious privilege activity: ' + ', '.join(sorted(set(priv_hits))),
                    {EV_HOST: host, EV_USER: event.user or 'unknown',
                     EV_PROCESS: process_name or None,
                     EV_COMMAND_LINE: command[:512] or None,
                     'indicators': sorted(set(priv_hits))},
                ))

        if 'TW-009' in enabled and command:
            persist_hits = []
            if _matches(_PERSIST_CRON_RE, command):
                persist_hits.append('cron_modification')
            if _matches(_PERSIST_SERVICE_RE, command):
                persist_hits.append('service_installation')
            if persist_hits:
                findings.append(self._finding(
                    event, self.registry.get('TW-009'),
                    'Suspicious persistence activity: ' + ', '.join(
                        sorted(set(persist_hits))),
                    {EV_HOST: host, EV_USER: event.user or 'unknown',
                     EV_PROCESS: process_name or None,
                     EV_COMMAND_LINE: command[:512] or None,
                     'indicators': sorted(set(persist_hits))},
                ))
        return findings

    def _match_port_scan(self, event, enabled):
        if 'TW-002' not in enabled:
            return []
        ports = event.metadata.get('ports', [])
        return [self._finding(
            event, self.registry.get('TW-002'),
            f'Port scan detected from {event.src_ip or "unknown"} - ports: {ports}',
            {EV_SOURCE_IP: event.src_ip or 'unknown',
             EV_PORTS: ports,
             EV_HOST: event.host or 'unknown'},
        )]

    def _match_traffic_spike(self, event, enabled):
        if 'TW-003' not in enabled:
            return []
        byte_count = event.metadata.get('bytes', 0)
        return [self._finding(
            event, self.registry.get('TW-003'),
            f'High outbound traffic: {byte_count} bytes',
            {EV_SOURCE_IP: event.src_ip or 'unknown',
             EV_BYTES: byte_count,
             EV_HOST: event.host or 'unknown'},
        )]

    def _match_dns(self, event, enabled):
        if 'TW-010' not in enabled or not event.domain:
            return []
        domain = event.domain.strip()
        if not _EXFIL_LIKE_DOMAIN_RE.match(domain):
            return []
        return [self._finding(
            event, self.registry.get('TW-010'),
            f'Possible exfiltration domain: {domain}',
            {EV_DOMAIN: domain, EV_HOST: event.host or 'unknown',
             EV_USER: event.user or 'unknown'},
        )]

    # -- finding helper --------------------------------------------------------

    def _finding(self, event, rule, description, evidence):
        return DetectionFinding(
            detection_id=_new_detection_id(),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            confidence=rule.confidence,
            description=description,
            event_ids=(event.event_id,),
            evidence=evidence,
            tags=rule.tags,
            mitre=rule.mitre,
            primary_event_id=event.event_id,
        )
