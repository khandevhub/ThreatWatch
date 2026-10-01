"""Investigation evidence model (Phase 3A).

A typed, deterministic, JSON-serializable evidence layer built only from
stored alerts, events, threat-intelligence rows, and rule metadata. Nothing
here fabricates data: unavailable evidence is represented explicitly as
``unavailable`` markers rather than invented values.

Every free-text value passes through :func:`redact_text` so passwords, API
keys, bearer tokens, and private-key material never enter investigation
packages, logs, or the AI-ready evidence bundle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

# Bounds keep every evidence structure finite regardless of input size.
EVIDENCE_SCHEMA_VERSION = 1
MAX_TEXT_LENGTH = 512
MAX_LIST_ITEMS = 50
MAX_TIMELINE_ENTRIES = 100

SECRET_KEY_PATTERN = re.compile(
    r'(?i)(?<![A-Za-z])'
    r'(authorization|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|'
    r'secret|password|passwd|pwd|passphrase|token|credential|private[_-]?key)'
    r'\b'
    r'([:=])\s*("?)([^\s",;]+)')
_BEARER_PATTERN = re.compile(r'(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+')
_PRIVATE_KEY_PATTERN = re.compile(
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')


def redact_text(value, limit=MAX_TEXT_LENGTH):
    """Mask secret material and bound length; deterministic and idempotent.

    Free-text fields (command lines, messages, metadata) may legitimately
    contain credentials; they are masked before evidence is built. The key
    pattern matches prefixed variable names too (INGEST_TOKEN=, JEV_API_KEY=)
    so Phase 4 knowledge ingestion never indexes such values.
    """
    if value is None:
        return None
    text = str(value)
    text = _PRIVATE_KEY_PATTERN.sub('***PRIVATE_KEY_REDACTED***', text)
    # Bearer tokens first so 'Authorization: Bearer <token>' cannot leak the
    # token as a residual word after the key=value mask runs.
    text = _BEARER_PATTERN.sub('Bearer ***REDACTED***', text)
    text = SECRET_KEY_PATTERN.sub(
        lambda match: f'{match.group(1)}{match.group(2)}{match.group(3)}***REDACTED***',
        text)
    if len(text) > limit:
        text = text[:limit - 3] + '...'
    return text


@dataclass(frozen=True)
class TimelineEntry:
    """One chronologically ordered investigation timeline entry."""

    timestamp: str | None
    event_type: str | None
    source: str | None
    host: str | None
    user: str | None
    src_ip: str | None
    dst_ip: str | None
    action: str | None
    event_id: str | None = None
    correlation_id: str | None = None
    alert_id: int | None = None
    related_alert: str | None = None      # rule code of the related alert
    timestamp_available: bool = True

    def sort_key(self):
        # Missing timestamps sort last, deterministically, after real ones;
        # identical timestamps tie-break on event_id then alert_id.
        return (0 if self.timestamp else 1, self.timestamp or '',
                self.event_id or '', self.alert_id if self.alert_id is not None else -1)

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'timestamp_available': self.timestamp_available,
            'event_type': self.event_type,
            'source': self.source,
            'host': self.host,
            'user': self.user,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'action': self.action,
            'event_id': self.event_id,
            'correlation_id': self.correlation_id,
            'alert_id': self.alert_id,
            'related_alert': self.related_alert,
        }


def build_timeline(event_rows, correlation_id=None, related_alert=None,
                   max_entries=MAX_TIMELINE_ENTRIES):
    """Build a deterministically ordered timeline from event rows.

    ``event_rows`` are sqlite3.Row-like objects from the events table.
    Malformed rows (missing event_time or event_type) are kept and flagged
    rather than dropped, so investigations can see that data was damaged.
    """
    entries = []
    for row in event_rows:
        get = row.get if hasattr(row, 'get') else (lambda key, r=row: r[key] if key in r.keys() else None)
        try:
            timestamp = get('event_time')
        except (IndexError, KeyError):
            timestamp = None
        event_type = get('event_type')
        timestamp_ok = isinstance(timestamp, str) and bool(timestamp.strip())
        type_ok = isinstance(event_type, str) and bool(event_type.strip())
        entries.append(TimelineEntry(
            timestamp=redact_text(timestamp, 64) if timestamp_ok else None,
            timestamp_available=timestamp_ok,
            event_type=redact_text(event_type, 128) if type_ok else None,
            source=redact_text(get('source'), 256),
            host=redact_text(get('host'), 256),
            user=redact_text(get('user'), 256),
            src_ip=get('src_ip'),
            dst_ip=get('dst_ip'),
            action=redact_text(get('action'), 128),
            event_id=get('event_id'),
            correlation_id=correlation_id,
            related_alert=related_alert,
        ))
    entries.sort(key=lambda entry: entry.sort_key())
    total = len(entries)
    return {'total_events': total,
            'entries': [entry.to_dict() for entry in entries[:max_entries]],
            'truncated': total > max_entries}


@dataclass
class Evidence:
    """Structured evidence supporting one SOC alert (Phase 3A schema)."""

    alert_id: int | None = None
    detection_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    rule_code: str | None = None
    severity: str | None = None
    description: str | None = None
    risk_score: int | None = None
    risk_band: str | None = None
    risk_factors: dict = field(default_factory=dict)
    risk_explanation: str | None = None
    correlation_id: str | None = None
    source_ips: list = field(default_factory=list)
    destination_ips: list = field(default_factory=list)
    hostnames: list = field(default_factory=list)
    usernames: list = field(default_factory=list)
    processes: list = field(default_factory=list)
    commands: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    hashes: list = field(default_factory=list)
    event_ids: list = field(default_factory=list)
    event_count: int = 0
    alert_time: str | None = None
    unavailable: list = field(default_factory=list)

    def mark_unavailable(self, item):
        if item not in self.unavailable:
            self.unavailable.append(item)

    def to_dict(self):
        return {
            'schema_version': EVIDENCE_SCHEMA_VERSION,
            'alert_id': self.alert_id,
            'detection_id': self.detection_id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'rule_code': self.rule_code,
            'severity': self.severity,
            'description': redact_text(self.description, 1024),
            'risk_score': self.risk_score,
            'risk_band': self.risk_band,
            'risk_factors': dict(sorted(self.risk_factors.items())),
            'risk_explanation': redact_text(self.risk_explanation, 1024),
            'correlation_id': self.correlation_id,
            'alert_time': self.alert_time,
            'entities': {
                'source_ips': list(self.source_ips),
                'destination_ips': list(self.destination_ips),
                'hostnames': list(self.hostnames),
                'usernames': list(self.usernames),
                'processes': list(self.processes),
                'commands': list(self.commands),
                'domains': list(self.domains),
                'urls': list(self.urls),
                'hashes': list(self.hashes),
            },
            'event_ids': list(self.event_ids),
            'event_count': self.event_count,
            'unavailable': list(self.unavailable),
        }
