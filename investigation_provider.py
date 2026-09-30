"""AI investigation provider interface (Phase 3G).

A provider-neutral abstraction for a future AI/RAG layer. Providers are
strictly advisory: they read a completed investigation package and may add
an ``ai_perspective`` section, but they never block the SOC pipeline, never
mutate detection results, and never make network calls here. Jev remains
the separate structured-decision layer; this interface does not replace it.

Phase 3 ships two offline implementations only:

- ``MockInvestigationProvider``: deterministic summaries/hypotheses derived
  from the package content (used by tests and offline demos).
- ``DisabledInvestigationProvider``: always returns nothing; the default.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger('threatwatch.investigation_provider')

PROVIDER_NAME_MOCK = 'mock'
PROVIDER_NAME_DISABLED = 'disabled'
AI_PERSPECTIVE_KEY = 'ai_perspective'


class InvestigationProvider:
    """Interface for future AI investigation providers (offline contract)."""

    name = 'abstract'

    def available(self):
        return False

    def investigate(self, package):
        """Return an advisory analysis dict for the package, or None."""
        raise NotImplementedError

    def summarize(self, package):
        """Return a bounded plain-text summary, or None."""
        raise NotImplementedError

    def generate_hypotheses(self, package):
        """Return a list of deterministic investigation hypotheses."""
        raise NotImplementedError


def _entities_of(package):
    evidence = package.get('evidence', {})
    entities = evidence.get('entities', {})
    return {
        'source_ips': entities.get('source_ips', []),
        'usernames': entities.get('usernames', []),
        'hostnames': entities.get('hostnames', []),
        'processes': entities.get('processes', []),
    }


class MockInvestigationProvider(InvestigationProvider):
    """Deterministic offline provider: derives output only from the package."""

    name = PROVIDER_NAME_MOCK

    def available(self):
        return True

    def summarize(self, package):
        alert = package.get('alert', {})
        risk = package.get('risk', {})
        evidence = package.get('evidence', {})
        entities = _entities_of(package)
        parts = [
            f"{alert.get('rule') or 'Unknown rule'} alert",
            f"risk {risk.get('score')}/100 ({risk.get('band')})",
            f"{evidence.get('event_count', 0)} correlated event(s)",
        ]
        if entities['source_ips']:
            parts.append('source ' + ', '.join(entities['source_ips'][:2]))
        if entities['usernames']:
            parts.append('accounts ' + ', '.join(entities['usernames'][:2]))
        return '; '.join(parts)

    def generate_hypotheses(self, package):
        """Deterministic hypotheses grounded in the package's own evidence."""
        hypotheses = []
        mitre = package.get('mitre', {}).get('techniques', [])
        entities = _entities_of(package)
        if entities['source_ips']:
            hypotheses.append(
                'The source may be automated: check for repeated activity from '
                + ', '.join(entities['source_ips'][:1]) + ' across other hosts.')
        if entities['usernames']:
            hypotheses.append(
                'Accounts may be targeted selectively: review authentication '
                'successes for ' + ', '.join(entities['usernames'][:1]) + '.')
        for technique in mitre[:2]:
            name = technique.get('technique_name') or technique.get('technique_id')
            hypotheses.append(
                f"Technique {technique.get('technique_id')} ({name}) suggests "
                f"looking for related persistence or staging activity.")
        if not hypotheses:
            hypotheses.append('Insufficient entity evidence; correlate with '
                              'adjacent telemetry for the affected host.')
        return hypotheses

    def investigate(self, package):
        return {
            'provider': self.name,
            'summary': self.summarize(package),
            'hypotheses': self.generate_hypotheses(package),
            'advisory_only': True,
        }


class DisabledInvestigationProvider(InvestigationProvider):
    """Default provider: AI investigation is off; everything returns None."""

    name = PROVIDER_NAME_DISABLED

    def available(self):
        return False

    def investigate(self, package):
        return None

    def summarize(self, package):
        return None

    def generate_hypotheses(self, package):
        return []


def make_investigation_provider(environ=None):
    """Build the configured provider (env-driven; no network in Phase 3)."""
    environ = os.environ if environ is None else environ
    enabled = (environ.get('INVESTIGATION_AI_ENABLED', '').strip().lower()
               in ('1', 'true', 'yes', 'on'))
    if enabled:
        return MockInvestigationProvider()
    return DisabledInvestigationProvider()


def apply_investigation_provider(package, provider):
    """Attach the provider's advisory perspective; never break the package.

    Any provider failure downgrades to an explicit ``unavailable`` marker —
    the SOC package itself is never modified beyond the one new key.
    """
    if provider is None or not provider.available():
        package[AI_PERSPECTIVE_KEY] = {
            'status': 'disabled',
            'provider': getattr(provider, 'name', PROVIDER_NAME_DISABLED),
        }
        return package
    try:
        analysis = provider.investigate(package)
        if analysis is None:
            package[AI_PERSPECTIVE_KEY] = {
                'status': 'unavailable', 'provider': provider.name,
            }
        else:
            package[AI_PERSPECTIVE_KEY] = {
                'status': 'ok', 'provider': provider.name, **analysis,
            }
    except Exception as exc:  # advisory layer must never break investigation
        logger.warning('Investigation provider failed (%s); continuing',
                       type(exc).__name__)
        package[AI_PERSPECTIVE_KEY] = {
            'status': 'unavailable', 'provider': provider.name,
            'reason': 'provider_error',
        }
    return package
