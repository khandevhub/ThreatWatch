"""Embedding-provider abstraction (Phase 4B).

A provider-neutral seam for turning text into vectors. Phase 4 ships only
offline providers: no network, no API key, no external model download. The
retrieval layer (Phase 4D) consumes this interface; the future LLM layer will
consume retrieval results — never this module directly.

Providers:

- ``HashingEmbeddingProvider`` ("local-hash"): deterministic, dependency-free
  hashed bag-of-features embeddings. The default ``local`` provider for dev,
  tests, and indexing. Not a semantic model — it is a documented, bounded
  substitute that keeps the whole pipeline offline and reproducible.
- ``MockEmbeddingProvider`` ("mock"): tiny deterministic unit vectors keyed by
  a fixed word vocabulary, designed so tests can assert exact cosine values.
- ``DisabledEmbeddingProvider`` ("disabled"): the default; embeds nothing.
"""
from __future__ import annotations

import hashlib
import math
import os
import re

PROVIDER_HASHING = 'local-hash'
PROVIDER_NAME_MOCK = 'mock'
PROVIDER_NAME_DISABLED = 'disabled'
# "local" selects the default offline implementation; the concrete provider is
# local-hash unless LOCAL_EMBEDDING_PROVIDER names another offline one.
PROVIDER_NAME_LOCAL = 'local'
LOCAL_PROVIDER_REGISTRY = (PROVIDER_HASHING,)

DEFAULT_DIMENSIONS = 256
MIN_DIMENSIONS = 8
MAX_DIMENSIONS = 2048
MAX_INPUT_CHARS = 8000
MAX_BATCH = 100

_TOKEN_PATTERN = re.compile(r'[a-z0-9_]{2,32}')

# Small fixed vocabulary for the mock provider (lowercased words only).
_MOCK_VECTORS = {
    'brute': (0.0, 0.8, 0.0, 0.6),
    'force': (0.0, 0.8, 0.0, 0.6),
    'spray': (0.0, 0.4, 0.9, 0.0),
    'password': (0.0, 0.4, 0.0, 0.9),
    'scan': (0.9, 0.0, 0.0, 0.0),
    'exfiltration': (0.0, 0.0, 0.0, 0.9),
    'powershell': (0.0, 0.0, 0.9, 0.0),
}


class EmbeddingError(ValueError):
    """Embedding request was malformed (size, batch, or dimension bounds)."""


def _l2_normalize(vector):
    norm = math.sqrt(sum(component * component for component in vector))
    if norm == 0.0:
        return [0.0] * len(vector)
    return [component / norm for component in vector]


def cosine_similarity(vector_a, vector_b):
    """Cosine of the angle between two equal-length vectors (deterministic)."""
    if not isinstance(vector_a, list) or not isinstance(vector_b, list):
        raise EmbeddingError('vectors must be lists of floats')
    if len(vector_a) != len(vector_b):
        raise EmbeddingError('vectors must have equal dimensions')
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for value_a, value_b in zip(vector_a, vector_b):
        try:
            fa = float(value_a)
            fb = float(value_b)
        except (TypeError, ValueError):
            raise EmbeddingError('vectors must contain only numbers') from None
        dot += fa * fb
        norm_a += fa * fa
        norm_b += fb * fb
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


class EmbeddingProvider:
    """Interface: embed single texts or bounded batches of texts."""

    name = 'abstract'

    def available(self):
        """Whether the provider can embed right now (offline = always True)."""
        return False

    def describe(self):
        """Return {provider, model, dimensions} metadata for storage."""
        raise NotImplementedError

    def embed_text(self, text):
        """Embed one bounded string; returns a list of floats."""
        raise NotImplementedError

    def embed_many(self, texts):
        """Embed a bounded batch; returns a list of float vectors."""
        raise NotImplementedError

    def _validate_text(self, text):
        if not isinstance(text, str):
            raise EmbeddingError('text must be a string')
        if len(text) > MAX_INPUT_CHARS:
            raise EmbeddingError(
                f'text exceeds maximum length of {MAX_INPUT_CHARS} characters')

    def _validate_batch(self, texts):
        if not isinstance(texts, (list, tuple)):
            raise EmbeddingError('texts must be a list of strings')
        if len(texts) > MAX_BATCH:
            raise EmbeddingError(f'batch exceeds maximum of {MAX_BATCH} texts')

    def _coerce_dimension(self, dimensions):
        try:
            dimensions = int(dimensions)
        except (TypeError, ValueError):
            raise EmbeddingError('dimensions must be an integer') from None
        if dimensions < MIN_DIMENSIONS or dimensions > MAX_DIMENSIONS:
            raise EmbeddingError(
                f'dimensions must be between {MIN_DIMENSIONS} and {MAX_DIMENSIONS}')
        return dimensions


class HashingEmbeddingProvider(EmbeddingProvider):
    """Deterministic hashed bag-of-n-grams embedding (offline, no downloads).

    Deterministic across runs and platforms: features come from a fixed
    tokenizer, hashed with blake2b into a fixed 2^64 bucket space, folded to
    the configured dimensionality with a deterministic sign, then
    L2-normalized. Two vectors are equal iff their inputs tokenize
    identically.
    """

    name = PROVIDER_HASHING

    def __init__(self, dimensions=DEFAULT_DIMENSIONS):
        self.dimensions = self._coerce_dimension(dimensions)

    def available(self):
        return True

    def describe(self):
        return {
            'provider': self.name,
            'model': 'hashing-v1',
            'dimensions': self.dimensions,
        }

    def _features(self, text):
        tokens = _TOKEN_PATTERN.findall(text.lower())
        features = list(tokens)
        for index in range(len(tokens) - 1):
            features.append(f'{tokens[index]}_{tokens[index + 1]}')
        return features

    def _embed_prepared(self, text):
        features = self._features(text)
        vector = [0.0] * self.dimensions
        for feature in features:
            digest = hashlib.blake2b(
                feature.encode('utf-8'), digest_size=8).digest()
            bucket = int.from_bytes(digest, 'big')
            index = bucket % self.dimensions
            sign = 1.0 if (bucket >> 63) & 1 else -1.0
            vector[index] += sign
        return _l2_normalize(vector)

    def embed_text(self, text):
        self._validate_text(text)
        return self._embed_prepared(text)

    def embed_many(self, texts):
        self._validate_batch(texts)
        return [self._embed_prepared(text) for text in texts]


class MockEmbeddingProvider(EmbeddingProvider):
    """Tiny deterministic unit vectors keyed by known words (for tests).

    Each known vocabulary word maps to a fixed 4-axis base vector (projected
    into the configured dimensionality; axes 4+ stay zero). Unknown words
    contribute nothing, so similarity comes only from vocabulary overlap —
    exact and assertable in tests.
    """

    name = PROVIDER_NAME_MOCK

    def __init__(self, dimensions=8):
        self.dimensions = self._coerce_dimension(dimensions)

    def available(self):
        return True

    def describe(self):
        return {
            'provider': self.name,
            'model': 'mock-vocabulary-v1',
            'dimensions': self.dimensions,
        }

    def _embed_prepared(self, text):
        vector = [0.0] * self.dimensions
        for token in _TOKEN_PATTERN.findall(text.lower()):
            base = _MOCK_VECTORS.get(token)
            if base is None:
                continue
            for axis, value in enumerate(base):
                if axis < self.dimensions:
                    vector[axis] += value
        return _l2_normalize(vector)

    def embed_text(self, text):
        self._validate_text(text)
        return self._embed_prepared(text)

    def embed_many(self, texts):
        self._validate_batch(texts)
        return [self._embed_prepared(text) for text in texts]


class DisabledEmbeddingProvider(EmbeddingProvider):
    """Default provider: embedding is off; embed_text/embed_many fail closed."""

    name = PROVIDER_NAME_DISABLED

    def available(self):
        return False

    def describe(self):
        return {'provider': self.name, 'model': None, 'dimensions': None}

    def embed_text(self, text):
        raise EmbeddingError('embedding provider is disabled')

    def embed_many(self, texts):
        raise EmbeddingError('embedding provider is disabled')


def _env_flag(environ, name, default=False):
    value = environ.get(name)
    if value is None or value == '':
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def make_embedding_provider(environ=None):
    """Env-driven provider factory (no network in Phase 4).

    ``EMBEDDING_PROVIDER`` selects: ``disabled`` (default), ``local`` (the
    offline hashing provider), or ``mock`` (tests). ``EMBEDDING_DIMENSIONS``
    sizes the local provider (8-2048).
    """
    environ = os.environ if environ is None else environ
    requested = (environ.get('EMBEDDING_PROVIDER') or 'disabled').strip().lower()
    if requested in ('', 'disabled', 'none', 'off'):
        return DisabledEmbeddingProvider()
    if requested == PROVIDER_NAME_LOCAL:
        requested = (environ.get('LOCAL_EMBEDDING_PROVIDER')
                     or PROVIDER_HASHING).strip().lower()
        if requested not in LOCAL_PROVIDER_REGISTRY:
            raise EmbeddingError(
                f'unknown LOCAL_EMBEDDING_PROVIDER: {requested}')
    if requested == PROVIDER_HASHING:
        return HashingEmbeddingProvider(
            dimensions=environ.get('EMBEDDING_DIMENSIONS') or DEFAULT_DIMENSIONS)
    if requested == PROVIDER_NAME_MOCK:
        return MockEmbeddingProvider()
    raise EmbeddingError(f'unknown EMBEDDING_PROVIDER: {requested}')


def make_indexing_provider(environ=None):
    """Indexing defaults to the offline local provider when embedding is off.

    Indexing is an explicit admin action; it should not require opting in via
    env. Query-time embedding uses make_embedding_provider().
    """
    environ = os.environ if environ is None else environ
    provider = make_embedding_provider(environ)
    if provider.available():
        return provider
    return HashingEmbeddingProvider()
