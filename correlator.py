"""Lightweight local correlation for the SOC core.

Groups related findings that share an attacker indicator (source IP, domain,
or host) so their evidence can be merged into a stronger finding. Keeps the
original per-finding evidence, generates a stable correlation ID per group,
and suppresses duplicate alerts for the same (rule, indicator) pair within a
cooldown window. Deliberately SQLite/local-scale: one in-memory grouper plus
a persisted suppression table.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import logging
import sqlite3
import uuid

logger = logging.getLogger('threatwatch.correlator')

DEFAULT_COOLDOWN_SECONDS = 300


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def new_correlation_id():
    return str(uuid.uuid4())


@dataclass(frozen=True)
class CorrelationGroup:
    """Merged evidence for findings that share one attacker indicator."""

    correlation_id: str
    key: str                      # e.g. 'source_ip:203.0.113.9'
    rule_id: str                  # strongest rule in the group
    rule_name: str
    severity: str                 # highest severity in the group
    description: str
    event_ids: tuple
    evidence: dict
    tags: tuple
    mitre: tuple
    findings: tuple               # the merged DetectionFinding objects
    confidence: float = 0.7       # max member confidence

    def to_dict(self):
        return {
            'correlation_id': self.correlation_id,
            'key': self.key,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'event_ids': list(self.event_ids),
            'evidence': self.evidence,
            'tags': list(self.tags),
            'mitre': list(self.mitre),
        }


SEVERITY_RANK = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}


class Correlator:
    """Groups same-indicator findings and suppresses duplicate alerts."""

    def __init__(self, cooldown_seconds=DEFAULT_COOLDOWN_SECONDS):
        self.cooldown_seconds = cooldown_seconds

    # -- grouping ---------------------------------------------------------

    def group_findings(self, findings):
        """Group findings by shared attacker indicator.

        Returns a list of CorrelationGroup objects. A single finding yields a
        single-finding group (still gets a correlation ID so every alert is
        traceable through the same pipeline).
        """
        if not findings:
            return []
        buckets = {}
        for finding in findings:
            key = self._group_key(finding)
            buckets.setdefault(key, []).append(finding)

        groups = []
        for key, members in buckets.items():
            members.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
            lead = members[0]
            event_ids = []
            for finding in members:
                for event_id in finding.event_ids:
                    if event_id not in event_ids:
                        event_ids.append(event_id)
            evidence = self._merge_evidence(key, members)
            groups.append(CorrelationGroup(
                correlation_id=new_correlation_id(),
                key=key,
                rule_id=lead.rule_id,
                rule_name=lead.rule_name,
                severity=lead.severity,
                description=self._describe(key, members),
                event_ids=tuple(event_ids),
                evidence=evidence,
                tags=tuple(dict.fromkeys(
                    tag for finding in members for tag in finding.tags)),
                mitre=tuple(dict.fromkeys(
                    technique for finding in members for technique in finding.mitre)),
                findings=tuple(members),
                confidence=max(f.confidence for f in members),
            ))
        return groups

    def _group_key(self, finding):
        source_ip = finding.evidence.get('source_ip')
        if source_ip:
            return f'source_ip:{source_ip}'
        domain = finding.evidence.get('domain')
        if domain:
            return f'domain:{domain}'
        host = finding.evidence.get('hostname')
        if host and host != 'unknown':
            return f'host:{host}'
        return f'event:{finding.primary_event_id or finding.detection_id}'

    def _merge_evidence(self, key, members):
        evidence = {
            'correlation_key': key,
            'finding_count': len(members),
            'rule_ids': sorted({f.rule_id for f in members}),
        }
        source_ips = sorted({f.evidence.get('source_ip') for f in members
                             if f.evidence.get('source_ip')})
        if source_ips:
            evidence['source_ips'] = source_ips
        users = sorted({u for f in members for u in f.evidence.get('affected_users', [])
                        } | {f.evidence.get('username') for f in members
                             if f.evidence.get('username')})
        if users:
            evidence['affected_users'] = users
            evidence['affected_user_count'] = len(users)
        hosts = sorted({f.evidence.get('hostname') for f in members
                        if f.evidence.get('hostname') and f.evidence.get('hostname') != 'unknown'})
        if hosts:
            evidence['affected_hosts'] = hosts
            evidence['affected_host_count'] = len(hosts)
        event_count = sum(len(f.event_ids) for f in members)
        evidence['event_count'] = event_count
        processes = sorted({p for f in members for p in f.evidence.get('processes', [])
                            } | {f.evidence.get('process_name') for f in members
                                 if f.evidence.get('process_name')})
        if processes:
            evidence['processes'] = processes
        command_lines = sorted({c for f in members
                                for c in f.evidence.get('command_lines', [])
                                } | {f.evidence.get('command_line') for f in members
                                     if f.evidence.get('command_line')})
        if command_lines:
            evidence['command_lines'] = command_lines
        techniques = sorted({t for f in members for t in f.mitre})
        if techniques:
            evidence['mitre_techniques'] = techniques
        return evidence

    def _describe(self, key, members):
        rule_names = sorted({f.rule_name for f in members})
        kind, _, value = key.partition(':')
        label = {'source_ip': 'source', 'domain': 'domain', 'host': 'host'}.get(kind, kind)
        return (f'{len(members)} correlated finding(s) via {label} {value}: '
                f'{", ".join(rule_names)}')

    # -- duplicate suppression --------------------------------------------

    def init_suppression_table(self, connection):
        connection.execute('''
            CREATE TABLE IF NOT EXISTS alert_suppression (
                scope TEXT NOT NULL,
                indicator TEXT NOT NULL,
                last_alert_time TEXT NOT NULL,
                PRIMARY KEY (scope, indicator)
            )
        ''')

    def is_suppressed(self, connection, rule_id, indicator):
        """True when the same rule fired for the same indicator recently."""
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(seconds=self.cooldown_seconds)).isoformat(
                      timespec='microseconds').replace('+00:00', 'Z')
        row = connection.execute(
            'SELECT last_alert_time FROM alert_suppression '
            'WHERE scope = ? AND indicator = ?', (rule_id, indicator)).fetchone()
        return bool(row) and row['last_alert_time'] > cutoff

    def mark_alerted(self, connection, rule_id, indicator, timestamp=None):
        connection.execute('''
            INSERT INTO alert_suppression (scope, indicator, last_alert_time)
            VALUES (?, ?, ?)
            ON CONFLICT(scope, indicator) DO UPDATE SET
                last_alert_time = excluded.last_alert_time
        ''', (rule_id, indicator, timestamp or _now_iso()))
