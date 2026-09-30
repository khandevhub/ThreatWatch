"""Transparent, deterministic risk scoring for SOC findings.

The score is a bounded weighted sum of explicit factors. Every contribution
is returned so the UI/API can always explain *why* an alert received its
score. Jev never replaces this scoring; it only reads the result.
"""
from __future__ import annotations

from dataclasses import dataclass

from rules import SEVERITY_ORDER


@dataclass(frozen=True)
class RiskResult:
    """Deterministic risk score with per-factor explainability."""

    score: int                  # 0-100
    band: str                   # low | medium | high | critical
    factors: dict               # factor name -> points contributed
    explanation: str

    def to_dict(self):
        return {'score': self.score, 'band': self.band,
                'factors': dict(self.factors), 'explanation': self.explanation}


# Factor weights (sum of maximum contributions = 100).
W_SEVERITY = 30
W_INTEL = 25
W_USERS = 15
W_FREQUENCY = 15
W_HOSTS = 10
W_CONFIDENCE = 5

MAX_USERS = 5          # saturating: 5+ affected users give full user points
MAX_HOSTS = 3          # saturating: 3+ affected hosts give full host points
MAX_EVENTS = 40        # saturating: 40+ events in the window give full frequency points

_SEV_POINTS = {'HIGH': W_SEVERITY, 'MEDIUM': 18, 'LOW': 9}


def _band(score):
    if score >= 80:
        return 'critical'
    if score >= 60:
        return 'high'
    if score >= 35:
        return 'medium'
    return 'low'


def compute_risk(finding, enrichment=None, event_count=None):
    """Score one DetectionFinding deterministically.

    ``enrichment``: optional threat_intel.Enrichment for the finding's
    primary indicator (source IP, domain, ...).
    ``event_count``: total events backing the finding (correlation size);
    defaults to the finding's own event count.
    """
    factors = {}

    # 1. Severity of the rule that fired.
    factors['severity'] = _SEV_POINTS.get(finding.severity, W_SEVERITY)

    # 2. Threat-intelligence confidence for the primary indicator.
    intel_points = 0
    if enrichment is not None and enrichment.known_malicious:
        intel_points = round(W_INTEL * max(0.0, min(1.0, enrichment.confidence)))
    factors['threat_intel'] = intel_points

    # 3. Distinct affected users (saturating).
    user_count = _int_or(finding.evidence.get('affected_user_count'), 0)
    if user_count == 0 and finding.evidence.get('affected_users'):
        user_count = len(finding.evidence['affected_users'])
    factors['affected_users'] = round(W_USERS * min(1.0, user_count / MAX_USERS))

    # 4. Event volume backing the finding (saturating).
    count = _int_or(event_count, len(finding.event_ids))
    factors['frequency'] = round(W_FREQUENCY * min(1.0, count / MAX_EVENTS))

    # 5. Distinct affected hosts (saturating).
    host_count = _int_or(finding.evidence.get('affected_host_count'), 0)
    factors['affected_hosts'] = round(W_HOSTS * min(1.0, host_count / MAX_HOSTS))

    # 6. Detector confidence.
    factors['confidence'] = round(W_CONFIDENCE * max(0.0, min(1.0, finding.confidence)))

    score = max(0, min(100, sum(factors.values())))
    parts = ', '.join(f'{name}={points}' for name, points in factors.items())
    explanation = (
        f'{finding.rule_name} ({finding.rule_id}) severity={finding.severity}; '
        f'score {score}/100 from factors: {parts}; '
        f"intel={'known-malicious' if intel_points else 'none'}"
    )
    return RiskResult(score=score, band=_band(score), factors=factors,
                      explanation=explanation)


def _int_or(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
