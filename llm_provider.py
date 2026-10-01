"""Provider-neutral LLM abstraction (Phase 4F).

A minimal seam between ThreatWatch and a chat-completions LLM. The AI
investigation engine (Phase 4G/4H) calls ``complete_json`` and validates the
structured response itself; this module never interprets SOC data.

Providers:

- ``MockLLMProvider`` ("mock"): deterministic offline provider for tests and
  demos. Produces a valid structured response grounded in the ``manifest``
  that accompanies every request — no network, no API key.
- ``DisabledLLMProvider`` ("disabled"): the default; the AI layer stays off.
- ``OpenAICompatibleLLMProvider`` ("openai-compatible"): talks to any
  OpenAI-compatible chat-completions endpoint configured via environment
  variables. Uses only the standard library (urllib) — no extra dependency.

Security invariants:

- Credentials come only from ``AI_LLM_API_KEY`` / ``AI_LLM_API_KEY_FILE`` and
  are never logged, never returned in results, and never sent to browsers.
- The endpoint is fixed by configuration; API clients can never choose one.
- HTTP(S) is enforced; plain HTTP is allowed only for explicit loopback
  endpoints (local model servers such as Ollama).
- Prompts and outputs are bounded; failures raise a controlled ``LLMError``.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger('threatwatch.llm')

PROVIDER_NAME_MOCK = 'mock'
PROVIDER_NAME_DISABLED = 'disabled'
PROVIDER_NAME_OPENAI_COMPATIBLE = 'openai-compatible'

DEFAULT_ENDPOINT = 'https://api.openai.com/v1/chat/completions'
DEFAULT_MODEL = 'gpt-4o-mini'

MAX_PROMPT_CHARS = 24000            # ~6k tokens; hard prompt bound
MAX_SYSTEM_CHARS = 8000
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 120
DEFAULT_TIMEOUT_SECONDS = 20
MIN_MAX_OUTPUT_TOKENS = 64
MAX_MAX_OUTPUT_TOKENS = 4000
DEFAULT_MAX_OUTPUT_TOKENS = 800
MIN_TEMPERATURE = 0.0
MAX_TEMPERATURE = 2.0
DEFAULT_TEMPERATURE = 0.2
MAX_RESPONSE_CHARS = 60000          # oversized responses are rejected


class LLMError(RuntimeError):
    """An LLM request failed (config, network, timeout, or bad output)."""


class LLMProvider:
    """Interface: one bounded JSON-completion request at a time."""

    name = 'abstract'

    def available(self):
        raise NotImplementedError

    def describe(self):
        """Return {provider, model} metadata (never credentials)."""
        raise NotImplementedError

    def complete_json(self, system_prompt, user_prompt, manifest=None,
                      max_output_tokens=None):
        """Return the model's parsed JSON object for one request.

        ``manifest`` is an optional structured summary of the allowed
        evidence/knowledge references (see ai_investigation.py). Deterministic
        providers may use it to ground their output; remote providers ignore
        it (grounding is enforced by response validation instead).
        """
        raise NotImplementedError

    @staticmethod
    def _validate_prompts(system_prompt, user_prompt):
        if not isinstance(system_prompt, str) or not system_prompt.strip():
            raise LLMError('system prompt must be a non-empty string')
        if not isinstance(user_prompt, str) or not user_prompt.strip():
            raise LLMError('user prompt must be a non-empty string')
        if len(system_prompt) > MAX_SYSTEM_CHARS:
            raise LLMError(
                f'system prompt exceeds {MAX_SYSTEM_CHARS} characters')
        if len(user_prompt) > MAX_PROMPT_CHARS:
            raise LLMError(
                f'user prompt exceeds {MAX_PROMPT_CHARS} characters')


class MockLLMProvider(LLMProvider):
    """Deterministic offline provider: output derived only from the request.

    The mock reads the manifest (allowed references) and produces a valid
    structured AI-investigation response without any network access. It
    deliberately echoes manifest facts so tests can assert grounding.
    """

    name = PROVIDER_NAME_MOCK

    def __init__(self, fail_after=None):
        self._calls = 0
        self._fail_after = fail_after

    def available(self):
        return True

    def describe(self):
        return {'provider': self.name, 'model': 'mock-copilot-v1'}

    def _next_response(self, system_prompt, user_prompt, manifest):
        manifest = manifest or {}
        alert_id = manifest.get('alert_id')
        rule_code = manifest.get('rule_code') or 'UNKNOWN_RULE'
        rule_id = manifest.get('rule_id') or ''
        techniques = list(manifest.get('mitre_techniques') or [])
        chunk_ids = list(manifest.get('chunk_ids') or [])
        event_ids = list(manifest.get('event_ids') or [])

        key_evidence = []
        if event_ids:
            key_evidence.append(
                f"Alert evidence includes event(s) {', '.join(event_ids[:3])}.")
        if chunk_ids:
            key_evidence.append(
                'Knowledge base documents corroborate the detection guidance '
                f'for {rule_code}.')
        if not key_evidence:
            key_evidence.append(
                'Limited evidence available; treat the assessment as provisional.')

        references = []
        if alert_id is not None:
            references.append({'type': 'alert_id', 'value': str(alert_id)})
        for event_id in event_ids[:2]:
            references.append({'type': 'event_id', 'value': event_id})
        for chunk_id in chunk_ids[:2]:
            references.append({'type': 'chunk_id', 'value': chunk_id})
        if rule_id:
            references.append({'type': 'rule_id', 'value': rule_id})

        mitre_assessment = [{
            'technique_id': technique,
            'relevance': 'consistent',
            'rationale': f'Detection rule evidence maps to {technique}.',
        } for technique in techniques[:3]]

        return {
            'summary': f'Advisory analysis of {rule_code} alert '
                       f'{alert_id if alert_id is not None else "(unsaved)"} '
                       'based on stored evidence and knowledge base guidance.',
            'assessment': 'Deterministic mock assessment: the deterministic '
                          'evidence is consistent with the alert; validate '
                          'against adjacent telemetry before concluding.',
            'priority': 'medium',
            'malicious_likelihood': 0.4,
            'false_positive_likelihood': 0.3,
            'confidence': 0.5,
            'key_evidence': key_evidence,
            'mitre_assessment': mitre_assessment,
            'recommended_actions': [
                {'action': 'Review the alert timeline in the investigation '
                           'package.',
                 'reason': 'Grounded in the stored alert evidence.',
                 'reference': {'type': 'alert_id', 'value': str(alert_id)}
                 if alert_id is not None else None},
                {'action': 'Compare with knowledge base guidance for the rule.',
                 'reason': 'Retrieved knowledge corroborates the next steps.',
                 'reference': {'type': 'chunk_id', 'value': chunk_ids[0]}
                 if chunk_ids else None},
            ],
            'investigation_questions': [
                'What adjacent telemetry exists for the affected entities?',
                'Has this rule fired historically for the same indicator?',
            ],
            'source_references': references,
        }

    def complete_json(self, system_prompt, user_prompt, manifest=None,
                      max_output_tokens=None):
        self._validate_prompts(system_prompt, user_prompt)
        self._calls += 1
        if self._fail_after is not None and self._calls > self._fail_after:
            raise LLMError('mock provider simulated failure')
        return self._next_response(system_prompt, user_prompt, manifest)


class DisabledLLMProvider(LLMProvider):
    """Default provider: the AI copilot is off; every request fails closed."""

    name = PROVIDER_NAME_DISABLED

    def available(self):
        return False

    def describe(self):
        return {'provider': self.name, 'model': None}

    def complete_json(self, system_prompt, user_prompt, manifest=None,
                      max_output_tokens=None):
        raise LLMError('llm provider is disabled')


class OpenAICompatibleLLMProvider(LLMProvider):
    """Chat-completions client for any OpenAI-compatible endpoint (stdlib).

    Configuration (environment variables):

    - ``AI_LLM_ENDPOINT``      chat-completions URL (default OpenAI's)
    - ``AI_LLM_MODEL``         model name (default ``gpt-4o-mini``)
    - ``AI_LLM_API_KEY``       bearer key (or ``AI_LLM_API_KEY_FILE``)
    - ``AI_LLM_TIMEOUT_SECONDS``   1-120 (default 20)
    - ``AI_LLM_MAX_OUTPUT_TOKENS`` 64-4000 (default 800)
    - ``AI_LLM_TEMPERATURE``   0.0-2.0 (default 0.2)
    """

    name = PROVIDER_NAME_OPENAI_COMPATIBLE

    def __init__(self, environ=None):
        environ = os.environ if environ is None else environ
        self.endpoint = (environ.get('AI_LLM_ENDPOINT') or DEFAULT_ENDPOINT).strip()
        self.model = (environ.get('AI_LLM_MODEL') or DEFAULT_MODEL).strip()
        if not self.endpoint.lower().startswith(('https://', 'http://')):
            raise LLMError('AI_LLM_ENDPOINT must be an http(s) URL')
        if self.endpoint.lower().startswith('http://'):
            # Plain HTTP only for explicit loopback endpoints (local servers).
            from urllib.parse import urlparse
            host = (urlparse(self.endpoint).hostname or '').lower()
            if host not in ('127.0.0.1', 'localhost', '::1'):
                raise LLMError(
                    'plain-text HTTP is only allowed for loopback endpoints')
        self.api_key = self._load_api_key(environ)
        self.timeout_seconds = self._bounded_number(
            environ.get('AI_LLM_TIMEOUT_SECONDS'),
            DEFAULT_TIMEOUT_SECONDS, MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS,
            'AI_LLM_TIMEOUT_SECONDS')
        self.default_max_output_tokens = self._bounded_number(
            environ.get('AI_LLM_MAX_OUTPUT_TOKENS'),
            DEFAULT_MAX_OUTPUT_TOKENS, MIN_MAX_OUTPUT_TOKENS,
            MAX_MAX_OUTPUT_TOKENS, 'AI_LLM_MAX_OUTPUT_TOKENS')
        self.temperature = self._bounded_number(
            environ.get('AI_LLM_TEMPERATURE'), DEFAULT_TEMPERATURE,
            MIN_TEMPERATURE, MAX_TEMPERATURE, 'AI_LLM_TEMPERATURE')
        if not self.model or len(self.model) > 128:
            raise LLMError('AI_LLM_MODEL must be a short non-empty string')

    @staticmethod
    def _bounded_number(raw, default, minimum, maximum, name):
        if raw is None or str(raw).strip() == '':
            return default
        try:
            value = float(raw)
        except (TypeError, ValueError):
            raise LLMError(f'{name} must be a number') from None
        if not minimum <= value <= maximum:
            raise LLMError(f'{name} must be between {minimum} and {maximum}')
        return value

    @staticmethod
    def _load_api_key(environ):
        key_file = environ.get('AI_LLM_API_KEY_FILE')
        if key_file:
            try:
                with open(key_file, 'r', encoding='utf-8') as stream:
                    return stream.read().strip()
            except OSError as exc:
                raise LLMError('could not read AI_LLM_API_KEY_FILE') from None
        return (environ.get('AI_LLM_API_KEY') or '').strip()

    def available(self):
        return bool(self.api_key) or self.endpoint.lower().startswith('http://')

    def describe(self):
        # Deliberately excludes the endpoint and any credential material.
        return {'provider': self.name, 'model': self.model}

    def complete_json(self, system_prompt, user_prompt, manifest=None,
                      max_output_tokens=None):
        self._validate_prompts(system_prompt, user_prompt)
        if not self.api_key:
            raise LLMError('AI LLM API key is not configured')
        tokens = self.default_max_output_tokens
        if max_output_tokens is not None:
            try:
                tokens = int(max_output_tokens)
            except (TypeError, ValueError):
                raise LLMError('max_output_tokens must be an integer') from None
            if not MIN_MAX_OUTPUT_TOKENS <= tokens <= MAX_MAX_OUTPUT_TOKENS:
                raise LLMError(
                    f'max_output_tokens must be between '
                    f'{MIN_MAX_OUTPUT_TOKENS} and {MAX_MAX_OUTPUT_TOKENS}')
        payload = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt},
            ],
            'temperature': self.temperature,
            'max_tokens': tokens,
            'response_format': {'type': 'json_object'},
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}',
            },
            method='POST')
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) \
                    as response:
                body = response.read(MAX_RESPONSE_CHARS + 1)
        except urllib.error.HTTPError as exc:
            logger.warning('LLM endpoint returned HTTP %s', exc.code)
            raise LLMError(f'llm endpoint returned HTTP {exc.code}') from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning('LLM endpoint unreachable (%s)', type(exc).__name__)
            raise LLMError('llm endpoint unreachable') from None
        if len(body) > MAX_RESPONSE_CHARS:
            raise LLMError('llm response exceeds maximum size')
        try:
            parsed = json.loads(body.decode('utf-8'))
        except (TypeError, ValueError):
            raise LLMError('llm response was not valid JSON') from None
        try:
            content = parsed['choices'][0]['message']['content']
        except (KeyError, IndexError, TypeError):
            raise LLMError('llm response had no message content') from None
        return self._extract_json_object(content)

    @staticmethod
    def _extract_json_object(content):
        """Extract the first JSON object from model prose (tolerant)."""
        if not isinstance(content, str):
            raise LLMError('llm content was not a string')
        text = content.strip()
        if text.startswith('```'):
            lines = text.splitlines()
            lines = lines[1:] if lines and lines[0].startswith('```') else lines
            while lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            text = '\n'.join(lines).strip()
        try:
            value = json.loads(text)
        except (TypeError, ValueError):
            start = text.find('{')
            end = text.rfind('}')
            if start == -1 or end <= start:
                raise LLMError('llm content contained no JSON object') from None
            try:
                value = json.loads(text[start:end + 1])
            except (TypeError, ValueError):
                raise LLMError('llm content was not parseable JSON') from None
        if not isinstance(value, dict):
            raise LLMError('llm content was not a JSON object')
        return value


def _env_flag(environ, name, default=False):
    value = environ.get(name)
    if value is None or value == '':
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def make_llm_provider(environ=None):
    """Env-driven LLM factory. Default (and test) path is fully offline.

    ``AI_LLM_PROVIDER`` selects ``disabled`` (default), ``mock`` (deterministic
    offline), or ``openai-compatible`` (real endpoint; requires configuration).
    """
    environ = os.environ if environ is None else environ
    requested = (environ.get('AI_LLM_PROVIDER') or 'disabled').strip().lower()
    if requested in ('', 'disabled', 'none', 'off'):
        return DisabledLLMProvider()
    if requested == PROVIDER_NAME_MOCK:
        return MockLLMProvider()
    if requested == PROVIDER_NAME_OPENAI_COMPATIBLE:
        return OpenAICompatibleLLMProvider(environ)
    raise LLMError(f'unknown AI_LLM_PROVIDER: {requested}')
