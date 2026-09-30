"""Investigation service (Phase 3B/3C/3E/3F).

Turns one stored SOC alert into a deterministic, bounded, JSON-serializable
investigation package suitable for an analyst or a future AI/RAG layer. The
service answers, structurally: what happened, why the alert fired, what
evidence supports it, which entities/indicators/techniques are involved,
what threat intelligence exists, which related alerts/events exist, the
current risk score, and what an analyst should investigate next.

Determinism: packages derive only from stored rows and rule metadata; no
wall-clock timestamps or randomness are embedded. Unavailable evidence is
listed explicitly under ``unavailable``. Bounded: every list is capped.
Secret-safe: free text passes through evidence.redact_text.
"""
from __future__ import annotations

import json
import sqlite3

from database import DB, connect
from evidence import MAX_LIST_ITEMS, Evidence, build_timeline, redact_text
from rules import ATTACK_TECHNIQUE_NAMES, load_rules

PACKAGE_SCHEMA_VERSION = 1
MAX_RELATED_ALERTS = 10
MAX_QUESTIONS = 8

# Canonical analyst next steps per ATT&CK technique (deterministic).
TECHNIQUE_INVESTIGATION = {
    'T1110': 'Review authentication logs for the targeted account(s).',
    'T1110.003': 'Enumerate accounts targeted from the source and check for successes.',
    'T1046': 'Identify services exposed on the targeted host.',
    'T1059.001': 'Recover the decoded script and check script-block logs on the host.',
    'T1027': 'Look for obfuscated payloads in related process telemetry.',
    'T1059': 'Trace the process tree that executed the command line.',
    'T1059.004': 'Review shell history and parent processes on the host.',
    'T1548.003': 'Audit sudo/sudoers changes on the affected host.',
    'T1078.003': 'Check whether the local account change was authorized.',
    'T1053.003': 'Inspect cron entries created or modified around the event time.',
    'T1543.002': 'Inspect the systemd unit file that was installed.',
    'T1048.003': 'Monitor DNS resolution for the look-alike domain.',
}

# Static next-step suggestions used when a rule carries no technique hints.
RULE_INVESTIGATION = {
    'TW-001': 'Determine whether the failures ended in a successful login.',
    'TW-002': 'Correlate the scanned ports with exposed services.',
    'TW-003': 'Confirm the traffic volume against a known-good baseline.',
}


class InvestigationError(ValueError):
    """The requested alert does not exist or cannot be investigated."""


def _rows_to_dicts(rows):
    return [dict(row) for row in rows]


def _safe_json(raw):
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, (dict, list)) else None


class InvestigationService:
    """Builds investigation packages for stored SOC alerts."""

    def __init__(self, db_file=None):
        self.db_file = db_file or DB
        self._registry = load_rules()

    # -- main entry ----------------------------------------------------------

    def build_investigation(self, alert_id):
        """Return the full investigation package for one alert id."""
        with connect(self.db_file) as connection:
            connection.row_factory = sqlite3.Row
            alert = connection.execute(
                'SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
            if alert is None:
                raise InvestigationError(f'alert {alert_id} not found')
            evidence = self._build_evidence(connection, alert)
            event_rows = self._alert_events(connection, evidence)
            timeline = build_timeline(
                event_rows, correlation_id=evidence.correlation_id,
                related_alert=evidence.rule_code)
            threat_intel = self._threat_intel_section(connection, evidence)
            mitre = self._mitre_section(alert, evidence)
            related = self._related_alerts(connection, evidence)
            indicators = self._indicators_section(evidence, threat_intel)
            questions = self.investigation_questions(evidence, mitre)
            alert_view = _safe_public_alert(alert)
        package = {
            'package_schema_version': PACKAGE_SCHEMA_VERSION,
            'alert': alert_view,
            'risk': {
                'score': evidence.risk_score,
                'band': evidence.risk_band,
                'factors': evidence.risk_factors,
                'explanation': evidence.risk_explanation,
            },
            'evidence': evidence.to_dict(),
            'timeline': timeline,
            'indicators': indicators,
            'threat_intel': threat_intel,
            'mitre': mitre,
            'related_alerts': related,
            'investigation_questions': questions,
        }
        return package

    # -- sections ------------------------------------------------------------

    def _build_evidence(self, connection, alert):
        soc = _safe_json(alert['evidence_json']) or {}
        event_ids = list(_safe_json(alert['source_event_ids_json']) or [])
        evidence = Evidence(
            alert_id=alert['id'],
            detection_id=alert['detection_id'],
            rule_id=alert['rule_id'],
            rule_name=None,
            rule_code=alert['rule'],
            severity=alert['severity'],
            description=alert['details'],
            risk_score=alert['deterministic_risk_score'],
            risk_band=alert['risk_band'],
            risk_factors=_safe_json(alert['risk_factors_json']) or {},
            risk_explanation=alert['risk_explanation'],
            correlation_id=alert['correlation_id'],
            event_ids=event_ids[:MAX_LIST_ITEMS],
            alert_time=alert['time'],
        )
        rule = self._registry.get(alert['rule_id']) if alert['rule_id'] else None
        evidence.rule_name = rule.name if rule else alert['rule']
        if rule is None:
            evidence.mark_unavailable('rule_metadata')

        entities = soc.get('affected_users') or []
        evidence.usernames, _ = _sorted_unique(entities)
        evidence.source_ips, _ = _sorted_unique(soc.get('source_ips') or [])
        evidence.hostnames, _ = _sorted_unique(soc.get('affected_hosts') or [])

        events = self._alert_events(connection, evidence)
        for row in events:
            for target, key in ((evidence.source_ips, 'src_ip'),
                                (evidence.destination_ips, 'dst_ip'),
                                (evidence.hostnames, 'host'),
                                (evidence.usernames, 'user'),
                                (evidence.processes, 'process'),
                                (evidence.commands, 'command_line'),
                                (evidence.domains, 'domain'),
                                (evidence.urls, 'url'),
                                (evidence.hashes, 'file_hash')):
                value = row[key] if key in row.keys() else None
                if value:
                    target.append(str(value))
        evidence.source_ips, _ = _sorted_unique(evidence.source_ips)
        evidence.destination_ips, _ = _sorted_unique(evidence.destination_ips)
        evidence.hostnames, _ = _sorted_unique(evidence.hostnames)
        evidence.usernames, _ = _sorted_unique(evidence.usernames)
        evidence.processes, _ = _sorted_unique(
            redact_text(value, 256) for value in evidence.processes)
        evidence.commands, _ = _sorted_unique(
            redact_text(value) for value in evidence.commands)
        evidence.domains, _ = _sorted_unique(evidence.domains)
        evidence.urls, _ = _sorted_unique(
            redact_text(value, 1024) for value in evidence.urls)
        evidence.hashes, _ = _sorted_unique(evidence.hashes)

        evidence.event_count = len(evidence.event_ids)

        if evidence.risk_score is None:
            evidence.mark_unavailable('risk_score')
        if evidence.correlation_id is None:
            evidence.mark_unavailable('correlation_id')
        if not event_ids:
            evidence.mark_unavailable('source_event_ids')
        if not events and event_ids:
            evidence.mark_unavailable('source_events')
        return evidence

    def _alert_events(self, connection, evidence):
        """Fetch stored events for the alert's evidence, bounded and ordered."""
        ids = evidence.event_ids[:MAX_LIST_ITEMS]
        if not ids:
            return []
        placeholders = ','.join('?' for _ in ids)
        rows = connection.execute(
            f'SELECT * FROM events WHERE event_id IN ({placeholders})',
            tuple(ids)).fetchall()
        # Deterministic order independent of DB row order: by event_id.
        return sorted(_rows_to_dicts(rows), key=lambda row: row.get('event_id') or '')

    def _threat_intel_section(self, connection, evidence):
        """Threat-intel context from stored enrichment rows + intel lookups."""
        section = {'matches': [], 'unavailable': []}
        enrichment_rows = connection.execute(
            'SELECT key, value FROM alert_enrichment WHERE alert_id = ? ORDER BY key',
            (evidence.alert_id,)).fetchall()
        stored = {row['key']: row['value'] for row in enrichment_rows}
        if stored:
            section['matches'].append({
                'source': 'stored_alert_enrichment',
                'fields': dict(sorted(stored.items())),
            })
        try:
            from threat_intel import ThreatIntel
            import os
            intel = ThreatIntel()
            intel.load_csv(os.environ.get('THREAT_INTEL', 'threat_intel.csv'))
        except OSError:
            section['unavailable'].append('threat_intel_feed')
            return section
        for indicator in (evidence.source_ips + evidence.domains
                          + evidence.hashes + evidence.urls):
            enrichment = intel.lookup(indicator)
            # lookup() also returns entries for indicators it does NOT know
            # (known_malicious=False); only real feed hits are matches.
            if enrichment is None or not enrichment.known_malicious:
                continue
            section['matches'].append(enrichment.to_dict())
        if not section['matches']:
            section['unavailable'].append('threat_intel_matches')
        return section

    def _mitre_section(self, alert, evidence):
        """ATT&CK context using ONLY stored mappings and rule metadata.

        Techniques are attributed to the member rule that maps to them: for
        merged alerts the stored evidence carries ``rule_ids`` for every
        contributing rule, so e.g. T1110 (Brute Force) is attributed to TW-001
        even when the alert's primary rule is the spraying rule.
        """
        techniques = []
        stored = _safe_json(alert['mitre_techniques_json']) if evidence.alert_id else []
        soc = _safe_json(alert['evidence_json']) or {}
        member_rule_ids = soc.get('rule_ids') if isinstance(soc, dict) else None
        candidates = []
        for rule_id in ([evidence.rule_id] if evidence.rule_id else []) + (
                member_rule_ids if isinstance(member_rule_ids, list) else []):
            if isinstance(rule_id, str) and rule_id not in candidates:
                candidates.append(rule_id)
        for technique_id in (stored or [])[:MAX_LIST_ITEMS]:
            if not isinstance(technique_id, str):
                continue
            rule = None
            for rule_id in candidates:
                candidate = self._registry.get(rule_id)
                if candidate and technique_id in tuple(candidate.mitre):
                    rule = candidate
                    break
            rule = rule or (self._registry.get(evidence.rule_id)
                            if evidence.rule_id else None)
            techniques.append({
                'technique_id': technique_id,
                'technique_name': ATTACK_TECHNIQUE_NAMES.get(technique_id),
                'rule_id': rule.rule_id if rule else evidence.rule_id,
                'rule_name': rule.name if rule else evidence.rule_name,
                'correlation_id': evidence.correlation_id,
                'alert_id': evidence.alert_id,
                'evidence_summary': redact_text(evidence.description, 512),
                'suggested_next_step': TECHNIQUE_INVESTIGATION.get(technique_id),
            })
        if not techniques:
            return {'techniques': [], 'unavailable': ['mitre_mapping']}
        return {'techniques': techniques, 'unavailable': []}

    def _related_alerts(self, connection, evidence):
        """Related alerts: correlation members first, then same-rule history."""
        related = []
        seen_ids = {evidence.alert_id}
        if evidence.correlation_id:
            rows = connection.execute(
                'SELECT id, time, rule, severity, correlation_id FROM alerts '
                'WHERE correlation_id = ? AND id != ? ORDER BY id LIMIT ?',
                (evidence.correlation_id, evidence.alert_id, MAX_RELATED_ALERTS),
            ).fetchall()
            for row in rows:
                related.append(_related_view(row, relation='correlation'))
                seen_ids.add(row['id'])
        if len(related) < MAX_RELATED_ALERTS and evidence.rule_id:
            remaining = MAX_RELATED_ALERTS - len(related)
            placeholders = ','.join('?' for _ in seen_ids) or 'NULL'
            rows = connection.execute(
                f'SELECT id, time, rule, severity, correlation_id FROM alerts '
                f'WHERE rule_id = ? AND id NOT IN ({placeholders}) '
                f'ORDER BY id DESC LIMIT ?',
                (evidence.rule_id, *seen_ids, remaining),
            ).fetchall()
            for row in rows:
                related.append(_related_view(row, relation='same_rule'))
        if not related:
            return {'alerts': [], 'unavailable': ['related_alerts']}
        return {'alerts': related, 'unavailable': []}

    def _indicators_section(self, evidence, threat_intel):
        known = {match.get('indicator')
                 for match in threat_intel['matches'] if match.get('indicator')}
        indicators = []
        for indicator_type, values in (
                ('ip', evidence.source_ips + evidence.destination_ips),
                ('domain', evidence.domains),
                ('url', evidence.urls),
                ('hash', evidence.hashes)):
            for value in values:
                indicators.append({
                    'indicator': value,
                    'indicator_type': indicator_type,
                    'known_malicious': value in known,
                })
        indicators.sort(key=lambda item: (item['indicator_type'], item['indicator']))
        return {'indicators': indicators[:MAX_LIST_ITEMS],
                'truncated': len(indicators) > MAX_LIST_ITEMS}

    # -- analyst questions -----------------------------------------------------

    def investigation_questions(self, evidence, mitre):
        """Deterministic next-step questions derived only from evidence."""
        questions = []
        if evidence.source_ips:
            questions.append(
                f"What other activity has been observed from source IP "
                f"{evidence.source_ips[0]} in the surrounding window?")
        if evidence.usernames:
            users = ', '.join(evidence.usernames[:3])
            questions.append(
                f"Are the affected accounts ({users}) normally active from "
                f"these sources at this time?")
        if evidence.hostnames:
            questions.append(
                f"What else ran on host {evidence.hostnames[0]} around the alert time?")
        for technique in mitre.get('techniques', []):
            name = technique.get('technique_name') or technique['technique_id']
            questions.append(
                f"Has {technique['technique_id']} ({name}) been observed "
                f"elsewhere in the environment recently?")
        if evidence.correlation_id:
            questions.append(
                f"Do the alerts sharing correlation ID {evidence.correlation_id} "
                f"share the same origin?")
        if not evidence.usernames and not evidence.source_ips:
            questions.append('What adjacent telemetry exists for the affected host?')
        if len(questions) < MAX_QUESTIONS and evidence.rule_code:
            rule_next = RULE_INVESTIGATION.get(evidence.rule_id)
            if rule_next:
                questions.append(rule_next)
            else:
                questions.append(
                    f"How often does rule {evidence.rule_code} usually fire, and is "
                    f"this rate unusual?")
        return questions[:MAX_QUESTIONS]


def _related_view(row, relation):
    return {
        'alert_id': row['id'],
        'time': row['time'],
        'rule': row['rule'],
        'severity': row['severity'],
        'correlation_id': row['correlation_id'],
        'relation': relation,
    }


def _safe_public_alert(alert):
    """Alert view for packages: SOC fields only; free text redacted."""
    return {
        'alert_id': alert['id'],
        'time': alert['time'],
        'rule': alert['rule'],
        'rule_id': alert['rule_id'],
        'severity': alert['severity'],
        'details': redact_text(alert['details'], 1024),
        'detection_id': alert['detection_id'],
        'correlation_id': alert['correlation_id'],
        'investigation_status': alert['investigation_status'],
        'jev_priority': alert['jev_priority'],
        'jev_attack_category': alert['jev_attack_category'],
        'jev_status': alert['jev_status'],
    }


def _sorted_unique(values, limit=MAX_LIST_ITEMS):
    ordered = sorted({str(value) for value in values if value})
    return ordered[:limit], len(ordered)
