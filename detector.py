"""SOC detection pipeline: persistence, detection, correlation, risk, decision.

Public behavior preserved from Phase 1: ``process_event`` stays atomic per
event, identical replays return False, alerts keep the legacy ``rule`` code
names (BRUTE_FORCE / PORT_SCAN / ...), and the same environment variables
configure thresholds. New: windowed password-spraying detection, structured
findings, correlation, explainable risk scoring, and the advisory Jev
decision layer (disabled by default; detection never depends on it).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from correlator import Correlator, new_correlation_id
from database import (DB, EventIdConflictError, connect, init_db,
                      record_ingestion_error)
from decision import get_decision, load_decision_config, make_provider
from detections import (DetectionEngine, EV_ATTEMPT_COUNT, EV_EVENT_IDS,
                        EV_SOURCE_IP, EV_USER, EV_USER_COUNT, EV_USERS)
from event_model import SecurityEvent
from rules import load_rules
from threat_intel import ThreatIntel

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('detector')


def _positive_setting(name, default):
    value = int(os.environ.get(name, str(default)))
    if value < 1:
        raise ValueError(f'{name} must be a positive integer')
    return value


DETECTION_WINDOW = _positive_setting('DETECTION_WINDOW', 60)
BRUTE_FORCE_THRESHOLD = _positive_setting('BRUTE_FORCE_THRESHOLD', 5)
THREAT_INTEL = os.environ.get('THREAT_INTEL', 'threat_intel.csv')

# SOC-core additions (Phase 2). Kept simple: environment-driven, like Phase 1.
CORRELATION_ENABLED = os.environ.get(
    'CORRELATION_ENABLED', 'true').strip().lower() not in ('0', 'false', 'no', 'off')
CORRELATION_COOLDOWN_SECONDS = _positive_setting('CORRELATION_COOLDOWN_SECONDS', 300)

_registry = load_rules()
_intel = ThreatIntel()
_intel.load_csv(THREAT_INTEL)
_engine = DetectionEngine(_registry, _intel)
_correlator = Correlator(cooldown_seconds=CORRELATION_COOLDOWN_SECONDS)
_decision_config = load_decision_config()
_provider = make_provider(_decision_config)

# Phase 1 compatibility: modules/tests read this mapping directly.
bad_ips = {indicator: tag for indicator, (tag, _conf, _src) in _intel._table.items()}


def load_threat_intel(path):
    """Phase 1 compatible loader (ip,tag CSV -> {ip: tag})."""
    intel = ThreatIntel()
    intel.load_csv(path)
    return {indicator: tag for indicator, (tag, _conf, _src) in intel._table.items()}


def reload_soc_components(environ=None):
    """Rebuild rule/intel/provider state (used by tests and config reloads)."""
    global _registry, _intel, _engine, _correlator, _provider, bad_ips
    _registry = load_rules(environ)
    _intel = ThreatIntel()
    _intel.load_csv(THREAT_INTEL)
    _engine = DetectionEngine(_registry, _intel)
    _correlator = Correlator(cooldown_seconds=CORRELATION_COOLDOWN_SECONDS)
    _provider = make_provider(load_decision_config(environ if environ is not None else {}))
    bad_ips = {indicator: tag for indicator, (tag, _c, _s) in _intel._table.items()}
    return _registry


# ---------------------------------------------------------------------------
# Windowed authentication state (brute force TW-001 + password spraying TW-004)
# ---------------------------------------------------------------------------

class WindowedAuthState:
    """Tracks failed logins per source IP within the configured windows.

    Writes through to SQLite (failed_login_attempts) so state survives
    restarts, exactly like Phase 1's brute-force counter.
    """

    def __init__(self, connection, registry):
        self.connection = connection
        brute = registry.get('TW-001')
        spray = registry.get('TW-004')
        self.brute_enabled = brute.enabled if brute else False
        self.spray_enabled = spray.enabled if spray else False
        self.brute = brute or None
        self.spray = spray or None

    def _prune(self, cutoff_text):
        self.connection.execute(
            'DELETE FROM failed_login_attempts WHERE event_time <= ?', (cutoff_text,))

    def evaluate(self, event):
        """Return findings for this auth_failed event; mutate window state."""
        now = datetime.fromisoformat(event.event_time.replace('Z', '+00:00'))
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        window_span = max(
            self.brute.window_seconds if self.brute else 0,
            self.spray.window_seconds if self.spray else 0,
        ) if (self.brute or self.spray) else 0
        cutoff = now - timedelta(seconds=window_span)
        cutoff_text = cutoff.astimezone(timezone.utc).isoformat(
            timespec='microseconds').replace('+00:00', 'Z')
        self._prune(cutoff_text)
        self.connection.execute(
            'INSERT OR IGNORE INTO failed_login_attempts (event_id, source_ip, event_time, user_name) '
            'VALUES (?, ?, ?, ?)',
            (event.event_id, event.src_ip or 'unknown', event.event_time, event.user))

        findings = []
        if self.spray_enabled:
            findings.extend(self._evaluate_spray(event, now))
        if self.brute_enabled:
            findings.extend(self._evaluate_brute(event, now))
        return findings

    def _evaluate_brute(self, event, now):
        from rules import SEVERITY_ORDER  # noqa: F401  (kept for parity)
        src = event.src_ip or 'unknown'
        cutoff = (now - timedelta(seconds=self.brute.window_seconds)).isoformat(
            timespec='microseconds').replace('+00:00', 'Z')
        count = self.connection.execute(
            'SELECT COUNT(*) FROM failed_login_attempts WHERE source_ip = ? AND event_time > ?',
            (src, cutoff)).fetchone()[0]
        if count < self.brute.threshold:
            return []
        targeted = [row[0] for row in self.connection.execute(
            'SELECT DISTINCT user_name FROM failed_login_attempts '
            'WHERE source_ip = ? AND event_time > ? AND user_name IS NOT NULL',
            (src, cutoff))]
        distinct_users = len(targeted)
        evidence = {
            EV_SOURCE_IP: src,
            EV_ATTEMPT_COUNT: count,
            EV_USER_COUNT: distinct_users,
            EV_USERS: targeted,
            EV_EVENT_IDS: self._event_ids(src, cutoff),
        }
        # One account hammered = classic brute force; several accounts = spray.
        if distinct_users <= 1:
            severity, rule_name = self.brute.severity, self.brute.name
            rule_id = self.brute.rule_id
        else:
            severity, rule_name = 'HIGH', self.brute.name
            rule_id = self.brute.rule_id
        finding = _make_finding(
            rule_id, rule_name, severity, self.brute.confidence,
            f'{count} failed logins against {distinct_users or 1} account(s) from {src} '
            f'within {self.brute.window_seconds}s',
            evidence, tags=self.brute.tags, mitre=self.brute.mitre,
            primary_event_id=event.event_id)
        # Consume the window like Phase 1 (counter reset after an alert).
        self.connection.execute(
            'DELETE FROM failed_login_attempts WHERE source_ip = ?', (src,))
        return [finding]

    def _evaluate_spray(self, event, now):
        """Password spraying: many distinct usernames from one source.

        Fires only when distinct-account count crosses the spray threshold —
        a single-account hammer stays with TW-001 brute force.
        """
        src = event.src_ip or 'unknown'
        cutoff = (now - timedelta(seconds=self.spray.window_seconds)).isoformat(
            timespec='microseconds').replace('+00:00', 'Z')
        users = [row[0] for row in self.connection.execute(
            'SELECT DISTINCT user_name FROM failed_login_attempts '
            'WHERE source_ip = ? AND event_time > ? AND user_name IS NOT NULL',
            (src, cutoff))]
        count = self.connection.execute(
            'SELECT COUNT(*) FROM failed_login_attempts WHERE source_ip = ? AND event_time > ?',
            (src, cutoff)).fetchone()[0]
        if len(users) < max(self.spray.threshold, 2) or count < len(users):
            return []
        finding = _make_finding(
            self.spray.rule_id, self.spray.name, self.spray.severity,
            self.spray.confidence,
            f'{count} failed logins against {len(users)} distinct accounts from '
            f'{src} within {self.spray.window_seconds}s (password spraying)',
            {EV_SOURCE_IP: src,
             EV_ATTEMPT_COUNT: count,
             EV_USER_COUNT: len(users),
             EV_USERS: users,
             EV_EVENT_IDS: self._event_ids(src, cutoff)},
            tags=self.spray.tags, mitre=self.spray.mitre,
            primary_event_id=event.event_id)
        return [finding]

    def _event_ids(self, src, cutoff):
        rows = self.connection.execute(
            'SELECT event_id FROM failed_login_attempts WHERE source_ip = ? AND event_time > ?',
            (src, cutoff)).fetchall()
        return [row[0] for row in rows]


def _make_finding(rule_id, rule_name, severity, confidence, description,
                  evidence, tags=(), mitre=(), primary_event_id=None):
    from detections import DetectionFinding
    import uuid as _uuid
    return DetectionFinding(
        detection_id=str(_uuid.uuid4()),
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        confidence=confidence,
        description=description,
        event_ids=tuple(evidence.get(EV_EVENT_IDS) or ()),
        evidence=evidence,
        tags=tuple(tags),
        mitre=tuple(mitre),
        primary_event_id=primary_event_id,
    )


# ---------------------------------------------------------------------------
# Persistence helpers (Phase 1 behavior preserved)
# ---------------------------------------------------------------------------

def _insert_alert(connection, event, rule, severity, details, enrichment=None):
    cursor = connection.execute(
        'INSERT INTO alerts (time, rule, severity, details, event_id) VALUES (?, ?, ?, ?, ?)',
        (event.ingestion_time, rule, severity, details, event.event_id),
    )
    alert_id = cursor.lastrowid
    if enrichment:
        connection.executemany(
            'INSERT INTO alert_enrichment (alert_id, key, value) VALUES (?, ?, ?)',
            [(alert_id, key, str(value)) for key, value in enrichment.items()],
        )
    return rule, severity, details


def _insert_soc_alert(connection, group, risk, decision, enrichment, correlation_id):
    """Persist one SOC alert with all Phase 2 fields."""
    rule_code = _registry.get(group.rule_id).code if _registry.get(group.rule_id) else group.rule_id
    cursor = connection.execute('''
        INSERT INTO alerts (
            time, rule, severity, details, event_id,
            detection_id, rule_id, deterministic_risk_score, risk_band,
            risk_factors_json, risk_explanation,
            jev_priority, jev_malicious_likelihood, jev_false_positive_likelihood,
            jev_investigation_required, jev_attack_category, jev_status,
            mitre_techniques_json, evidence_json, source_event_ids_json,
            correlation_id, investigation_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
    ''', (
        _now_iso(), rule_code, group.severity, group.description, group.event_ids[-1] if group.event_ids else None,
        group.findings[0].detection_id if group.findings else None,
        group.rule_id,
        risk.score, risk.band,
        json.dumps(risk.factors, sort_keys=True), risk.explanation,
        decision.get('priority'), decision.get('malicious_likelihood'),
        decision.get('false_positive_likelihood'), decision.get('investigation_required'),
        decision.get('attack_category'), decision.get('jev_status', 'fallback'),
        json.dumps(list(group.mitre)), json.dumps(group.evidence, sort_keys=True),
        json.dumps(list(group.event_ids)), correlation_id,
    ))
    alert_id = cursor.lastrowid
    if enrichment and enrichment.known_malicious:
        connection.execute(
            'INSERT OR REPLACE INTO alert_enrichment (alert_id, key, value) VALUES (?, ?, ?)',
            (alert_id, 'known_threat', 'true'))
        connection.execute(
            'INSERT OR REPLACE INTO alert_enrichment (alert_id, key, value) VALUES (?, ?, ?)',
            (alert_id, 'source_ip', enrichment.indicator))
    return alert_id, rule_code


def _now_iso():
    from database import utc_now
    return utc_now()


def _event_values(event):
    return (
        event.event_id, event.schema_version, event.event_time, event.ingestion_time,
        event.source, event.source_type, event.host, event.user, event.src_ip,
        event.dst_ip, event.src_port, event.dst_port, event.event_type, event.action,
        event.outcome, event.process, event.command_line, event.domain, event.url,
        event.file_hash, json.dumps(event.metadata, ensure_ascii=False, sort_keys=True),
    )


def _store_event(connection, event):
    cursor = connection.execute('''
        INSERT OR IGNORE INTO events (
            event_id, schema_version, event_time, ingestion_time, source, source_type,
            host, user_name, src_ip, dst_ip, src_port, dst_port, event_type, action,
            outcome, process, command_line, domain, url, file_hash, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', _event_values(event))
    if cursor.rowcount == 1:
        return True

    existing = connection.execute('''
        SELECT schema_version, source, source_type, host, user_name, src_ip, dst_ip,
               src_port, dst_port, event_type, action, outcome, process, command_line,
               domain, url, file_hash, metadata_json
        FROM events WHERE event_id = ?
    ''', (event.event_id,)).fetchone()
    if existing is None:
        raise sqlite3.IntegrityError('Event could not be persisted')
    current = (
        event.schema_version, event.source, event.source_type, event.host, event.user,
        event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.event_type,
        event.action, event.outcome, event.process, event.command_line, event.domain,
        event.url, event.file_hash,
        json.dumps(event.metadata, ensure_ascii=False, sort_keys=True),
    )
    if tuple(existing) != current:
        raise EventIdConflictError('event_id is already associated with different event data')
    return False


def _enrichment(src):
    """Phase 1 compatible enrichment rows for the legacy alert path."""
    return {
        'source_ip': src,
        'known_threat': 'true' if src in bad_ips else 'false',
    }


# ---------------------------------------------------------------------------
# SOC pipeline
# ---------------------------------------------------------------------------

def _run_soc_pipeline(connection, event, findings):
    """Correlate -> risk -> Jev -> persist SOC alert. Returns alert info."""
    groups = _correlator.group_findings(findings)
    alerts = []
    for group in groups:
        indicator = group.evidence.get('source_ips', [None])[0] \
            if group.evidence.get('source_ips') else None
        indicator = indicator or group.evidence.get('correlation_key', '').partition(':')[2] or None

        member_rules = {f.rule_id for f in group.findings} | {group.rule_id}
        if CORRELATION_ENABLED and indicator and all(
                _correlator.is_suppressed(connection, rule_id, indicator)
                for rule_id in member_rules):
            # Duplicate: every contributing rule already alerted for this
            # indicator inside the cooldown window.
            logger.debug('Suppressing duplicate SOC alert for %s/%s',
                         group.rule_id, indicator)
            continue
        # Escalation: at least one member rule is new for this indicator, so
        # the merged (stronger) finding alerts even if others were seen.

        enrichment = None
        if indicator:
            enrichment = _intel.lookup(indicator)
            # Phase 1 compatibility: bad_ips (mutatable in tests/ops) also
            # contributes enrichment, mirroring the legacy alert path.
            tag = bad_ips.get(indicator)
            if tag and not (enrichment and enrichment.known_malicious):
                from threat_intel import DEFAULT_CONFIDENCE, Enrichment
                enrichment = Enrichment(
                    indicator=indicator, indicator_type='ip',
                    known_malicious=True, confidence=DEFAULT_CONFIDENCE,
                    source='bad_ips')
            if enrichment is not None and enrichment.known_malicious:
                note = (tag or 'known_threat').upper()
                group = _with_intel_note(group, note)
        risk = compute_risk_for_group(group, enrichment)
        decision = get_decision(_provider, group, risk, enrichment)
        correlation_id = new_correlation_id()
        alert_id, rule_code = _insert_soc_alert(
            connection, group, risk, decision, enrichment, correlation_id)
        if not (enrichment and enrichment.known_malicious) and indicator:
            connection.execute(
                'INSERT OR REPLACE INTO alert_enrichment (alert_id, key, value) VALUES (?, ?, ?)',
                (alert_id, 'known_threat', 'false'))
            if event is not None and event.src_ip:
                connection.execute(
                    'INSERT OR REPLACE INTO alert_enrichment (alert_id, key, value) VALUES (?, ?, ?)',
                    (alert_id, 'source_ip', event.src_ip))
        if CORRELATION_ENABLED and indicator:
            # Suppress per contributing rule so a later single-rule group from
            # the same indicator (e.g. brute force after a spray alert) cannot
            # re-alert during the cooldown either.
            for member_rule_id in {f.rule_id for f in group.findings} | {group.rule_id}:
                _correlator.mark_alerted(connection, member_rule_id, indicator)
        connection.execute(
            'INSERT OR IGNORE INTO correlations (correlation_id, key, primary_rule_id, event_count, created_at) '
            'VALUES (?, ?, ?, ?, ?)',
            (correlation_id, group.key, group.rule_id, len(group.event_ids), _now_iso()))
        alerts.append({'alert_id': alert_id, 'rule': rule_code,
                       'severity': group.severity, 'risk': risk.score})
    return alerts


def _with_intel_note(group, note):
    """Return a copy of the group whose description carries the intel tag."""
    import dataclasses
    return dataclasses.replace(group, description=f'{group.description} [{note}]')


def compute_risk_for_group(group, enrichment):
    from risk import compute_risk
    lead_finding = group.findings[0] if group.findings else None
    if lead_finding is None:
        return None
    # Use the merged evidence for scoring: rebuild a lead finding whose
    # evidence includes correlation-derived user counts.
    from detections import DetectionFinding
    merged = DetectionFinding(
        detection_id=lead_finding.detection_id,
        rule_id=group.rule_id,
        rule_name=group.rule_name,
        severity=group.severity,
        confidence=group.confidence,
        description=group.description,
        event_ids=group.event_ids,
        evidence={**lead_finding.evidence,
                  'affected_user_count': group.evidence.get('affected_user_count', 0),
                  'affected_host_count': group.evidence.get('affected_host_count', 0)},
        tags=group.tags,
        mitre=group.mitre,
        primary_event_id=lead_finding.primary_event_id,
    )
    return compute_risk(merged, enrichment=enrichment,
                        event_count=group.evidence.get('event_count', len(group.event_ids)))


def process_event(evt, *, db_file=None, generated_event_id=None):
    """Persist and detect one event atomically; return False for an identical replay."""
    event = evt if isinstance(evt, SecurityEvent) else SecurityEvent.from_payload(
        evt, default_source='simulator', generated_event_id=generated_event_id)
    alert = None
    with connect(db_file or DB) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            if not _store_event(connection, event):
                connection.commit()
                return False
            windowed = WindowedAuthState(connection, _registry)
            findings = _engine.evaluate_event(event, windowed_state=windowed)
            if findings:
                alerts = _run_soc_pipeline(connection, event, findings)
                if alerts:
                    alert = (alerts[0]['rule'], alerts[0]['severity'],
                             f"risk={alerts[0]['risk']}")
            else:
                alert = _detect_legacy(connection, event)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    if alert:
        logger.info('[ALERT] %s %s %s %s', event.ingestion_time, *alert)
    return True


def _detect_legacy(connection, event):
    """Log-only fallback for event types no enabled rule consumed."""
    logger.debug('Unhandled event type: %s', event.event_type)
    return None


if __name__ == '__main__':
    init_db(DB)
    for _ in range(5):
        process_event({'type': 'auth_failed', 'src': '10.0.0.5'})
    print('Detector self-test complete. Check the alerts table in', DB)
