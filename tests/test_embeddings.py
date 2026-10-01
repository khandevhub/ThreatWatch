"""Phase 4B embedding provider tests: interface, determinism, bounds, failure."""
import math

import pytest

from embeddings import (
    DEFAULT_DIMENSIONS,
    DisabledEmbeddingProvider,
    EmbeddingError,
    HashingEmbeddingProvider,
    MAX_BATCH,
    MAX_INPUT_CHARS,
    MockEmbeddingProvider,
    cosine_similarity,
    make_embedding_provider,
    make_indexing_provider,
)


# -- provider interface ---------------------------------------------------------

def test_provider_interface_contract():
    from embeddings import EmbeddingProvider
    provider = EmbeddingProvider()
    assert provider.available() is False
    with pytest.raises(NotImplementedError):
        provider.describe()
    with pytest.raises(NotImplementedError):
        provider.embed_text('text')
    with pytest.raises(NotImplementedError):
        provider.embed_many(['text'])


# -- local hashing provider -----------------------------------------------------

def test_hashing_provider_deterministic_and_normalized():
    provider = HashingEmbeddingProvider()
    first = provider.embed_text('brute force authentication failures')
    second = provider.embed_text('brute force authentication failures')
    assert first == second
    assert len(first) == DEFAULT_DIMENSIONS
    norm = math.sqrt(sum(component * component for component in first))
    assert norm == pytest.approx(1.0, abs=1e-9)
    assert provider.describe() == {
        'provider': 'local-hash', 'model': 'hashing-v1',
        'dimensions': DEFAULT_DIMENSIONS}


def test_hashing_provider_separates_topics():
    provider = HashingEmbeddingProvider()
    auth = provider.embed_text('password spraying authentication failures')
    dns = provider.embed_text('dns exfiltration look-alike domain')
    same = provider.embed_text('password spraying authentication failures')
    assert cosine_similarity(auth, same) > 0.99
    assert cosine_similarity(auth, dns) < 0.3


def test_hashing_provider_batch_matches_single():
    provider = HashingEmbeddingProvider()
    texts = ['brute force', 'port scan', 'dns tunnel']
    batch = provider.embed_many(texts)
    assert len(batch) == len(texts)
    for text, vector in zip(texts, batch):
        assert vector == provider.embed_text(text)


def test_hashing_provider_dimension_validation():
    with pytest.raises(EmbeddingError):
        HashingEmbeddingProvider(dimensions=4)   # below MIN_DIMENSIONS
    with pytest.raises(EmbeddingError):
        HashingEmbeddingProvider(dimensions=99999)
    with pytest.raises(EmbeddingError):
        HashingEmbeddingProvider(dimensions='not-a-number')


# -- mock provider --------------------------------------------------------------

def test_mock_provider_exact_cosine_values():
    provider = MockEmbeddingProvider()
    brute = provider.embed_text('brute force attack')
    spray = provider.embed_text('password spraying')
    partial = provider.embed_text('brute force')
    unrelated = provider.embed_text('powershell encoded command')
    # Same vocabulary words -> identical direction; disjoint vocabulary -> 0.
    assert cosine_similarity(brute, partial) == pytest.approx(1.0)
    assert cosine_similarity(brute, unrelated) == 0.0
    assert cosine_similarity(spray, unrelated) == 0.0
    # Overlapping axes (both credential-attack words) -> related but not equal.
    related = cosine_similarity(brute, spray)
    assert 0.5 < related < 1.0


def test_mock_provider_deterministic_and_batched():
    provider = MockEmbeddingProvider()
    assert provider.embed_text('brute force') == provider.embed_text('brute force')
    batch = provider.embed_many(['brute force', 'port scan'])
    assert batch[0] == provider.embed_text('brute force')
    assert batch[1] == provider.embed_text('port scan')


# -- disabled provider ----------------------------------------------------------

def test_disabled_provider_fails_closed():
    provider = DisabledEmbeddingProvider()
    assert provider.available() is False
    with pytest.raises(EmbeddingError, match='disabled'):
        provider.embed_text('anything')
    with pytest.raises(EmbeddingError, match='disabled'):
        provider.embed_many(['anything'])
    assert provider.describe() == {
        'provider': 'disabled', 'model': None, 'dimensions': None}


# -- input validation -----------------------------------------------------------

def test_all_providers_reject_oversized_and_non_string_input():
    providers = [HashingEmbeddingProvider(), MockEmbeddingProvider()]
    for provider in providers:
        with pytest.raises(EmbeddingError):
            provider.embed_text('x' * (MAX_INPUT_CHARS + 1))
        with pytest.raises(EmbeddingError):
            provider.embed_text(None)
        with pytest.raises(EmbeddingError):
            provider.embed_text(12345)
        with pytest.raises(EmbeddingError):
            provider.embed_many(['ok'] * (MAX_BATCH + 1))
        with pytest.raises(EmbeddingError):
            provider.embed_many('not-a-list')


def test_cosine_similarity_validates_vectors():
    with pytest.raises(EmbeddingError):
        cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0])
    with pytest.raises(EmbeddingError):
        cosine_similarity([1.0, 'x'], [1.0, 0.0])
    with pytest.raises(EmbeddingError):
        cosine_similarity('not a vector', [1.0, 0.0])
    assert cosine_similarity([0.0, 0.0], [1.0, 0.0]) == 0.0


# -- factories ------------------------------------------------------------------

def test_factory_defaults_to_disabled():
    assert isinstance(make_embedding_provider({}), DisabledEmbeddingProvider)


def test_factory_selects_local_mock_and_rejects_unknown():
    local = make_embedding_provider({'EMBEDDING_PROVIDER': 'local'})
    assert isinstance(local, HashingEmbeddingProvider)
    mock = make_embedding_provider({'EMBEDDING_PROVIDER': 'mock'})
    assert isinstance(mock, MockEmbeddingProvider)
    with pytest.raises(EmbeddingError, match='unknown'):
        make_embedding_provider({'EMBEDDING_PROVIDER': 'openai'})
    with pytest.raises(EmbeddingError, match='unknown'):
        make_embedding_provider({
            'EMBEDDING_PROVIDER': 'local',
            'LOCAL_EMBEDDING_PROVIDER': 'not-a-provider'})


def test_factory_respects_dimension_environment():
    provider = make_embedding_provider({
        'EMBEDDING_PROVIDER': 'local', 'EMBEDDING_DIMENSIONS': '128'})
    assert provider.dimensions == 128
    with pytest.raises(EmbeddingError):
        make_embedding_provider({
            'EMBEDDING_PROVIDER': 'local', 'EMBEDDING_DIMENSIONS': '3'})


def test_indexing_factory_falls_back_to_local():
    assert isinstance(make_indexing_provider({}), HashingEmbeddingProvider)
    assert isinstance(
        make_indexing_provider({'EMBEDDING_PROVIDER': 'mock'}),
        MockEmbeddingProvider)
