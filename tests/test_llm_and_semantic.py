"""Phase 4E-4F tests: semantic embeddings and the LLM provider seam."""
import json

import pytest

from embeddings import (
    DisabledEmbeddingProvider,
    EmbeddingError,
    HashingEmbeddingProvider,
    MockEmbeddingProvider,
    PROVIDER_SEMANTIC,
    SemanticEmbeddingProvider,
    make_embedding_provider,
)
from llm_provider import (
    DisabledLLMProvider,
    LLMError,
    MAX_PROMPT_CHARS,
    MAX_RESPONSE_CHARS,
    MockLLMProvider,
    OpenAICompatibleLLMProvider,
    make_llm_provider,
)
from vector_store import VectorStore, VectorStoreError


# -- 4E: semantic provider -------------------------------------------------------

def test_semantic_provider_unavailable_without_package():
    provider = SemanticEmbeddingProvider()
    # fastembed is an optional dependency; the suite must not require it.
    try:
        import fastembed  # noqa: F401
        assert provider.available() is True
    except ImportError:
        assert provider.available() is False
        with pytest.raises(EmbeddingError, match='fastembed'):
            provider.embed_text('brute force')


def test_semantic_provider_model_metadata_and_validation():
    provider = SemanticEmbeddingProvider()
    assert provider.name == PROVIDER_SEMANTIC
    description = provider.describe()
    assert description['provider'] == PROVIDER_SEMANTIC
    assert description['model']
    assert isinstance(description['dimensions'], int)
    with pytest.raises(EmbeddingError):
        SemanticEmbeddingProvider(dimensions=2)
    with pytest.raises(EmbeddingError):
        SemanticEmbeddingProvider(dimensions='bad')


def test_semantic_provider_model_cache_is_reused():
    from embeddings import _SEMANTIC_MODEL_CACHE
    assert isinstance(_SEMANTIC_MODEL_CACHE, dict)


def test_existing_providers_regress_none():
    # The Phase 4A-4D providers remain untouched and deterministic.
    hashing = HashingEmbeddingProvider()
    assert hashing.embed_text('brute force') == hashing.embed_text('brute force')
    assert isinstance(MockEmbeddingProvider().embed_text('brute force'), list)
    assert DisabledEmbeddingProvider().available() is False


def test_vector_store_rejects_mismatched_embedding_models(tmp_path):
    store = VectorStore(db_file=str(tmp_path / 'k.sqlite'))
    vector = [1.0] * 8
    store.upsert('a#000', vector, 'a', 'content', 'detection_rule', 's',
                 embedding_model='hashing-v1')
    with pytest.raises(VectorStoreError, match='model mismatch'):
        store.upsert('b#000', vector, 'b', 'content', 'detection_rule', 's',
                     embedding_model='bge-small-en-v1.5')
    store.upsert('c#000', vector, 'c', 'content', 'detection_rule', 's',
                 embedding_model='hashing-v1')
    assert store.count() == 2
    with pytest.raises(VectorStoreError):
        store.upsert('d#000', vector, 'd', 'content', 'detection_rule', 's',
                     embedding_model='   ')


def test_semantic_factory_selectable_and_rejected_unknown():
    provider = make_embedding_provider({'EMBEDDING_PROVIDER': 'local-semantic'})
    assert isinstance(provider, SemanticEmbeddingProvider)
    custom = make_embedding_provider({
        'EMBEDDING_PROVIDER': 'local-semantic',
        'EMBEDDING_MODEL': 'Xenova/all-MiniLM-L6-v2',
        'EMBEDDING_DIMENSIONS': '384'})
    assert custom.model_name == 'Xenova/all-MiniLM-L6-v2'
    assert custom.dimensions == 384
    via_local = make_embedding_provider({
        'EMBEDDING_PROVIDER': 'local',
        'LOCAL_EMBEDDING_PROVIDER': 'local-semantic'})
    assert isinstance(via_local, SemanticEmbeddingProvider)
    with pytest.raises(EmbeddingError):
        make_embedding_provider({
            'EMBEDDING_PROVIDER': 'local',
            'LOCAL_EMBEDDING_PROVIDER': 'nonsense'})


# -- 4F: LLM providers ------------------------------------------------------------

def test_llm_disabled_provider_fails_closed():
    provider = DisabledLLMProvider()
    assert provider.available() is False
    with pytest.raises(LLMError, match='disabled'):
        provider.complete_json('system', 'user')


def test_llm_mock_provider_grounds_output_in_manifest():
    provider = MockLLMProvider()
    manifest = {
        'alert_id': 3, 'rule_code': 'PASSWORD_SPRAYING', 'rule_id': 'TW-004',
        'mitre_techniques': ['T1110.003'], 'chunk_ids': ['kb#000'],
        'event_ids': ['ev-1'],
    }
    response = provider.complete_json('system', 'user', manifest=manifest)
    values = {reference['value']
              for reference in response['source_references']}
    assert '3' in values and 'TW-004' in values
    assert response['priority'] in ('low', 'medium', 'high', 'critical')
    assert 0.0 <= response['confidence'] <= 1.0


def test_llm_prompt_bounds_enforced_for_all_providers():
    oversized = 'x' * (MAX_PROMPT_CHARS + 1)
    for provider in (MockLLMProvider(), DisabledLLMProvider()):
        with pytest.raises(LLMError):
            provider.complete_json('system', oversized)
    with pytest.raises(LLMError):
        MockLLMProvider().complete_json('', 'user')


def test_openai_compatible_provider_configuration_validation():
    provider = OpenAICompatibleLLMProvider({'AI_LLM_API_KEY': 'k' * 24})
    assert provider.describe() == {
        'provider': 'openai-compatible', 'model': 'gpt-4o-mini'}
    assert 'endpoint' not in provider.describe()
    with pytest.raises(LLMError):
        OpenAICompatibleLLMProvider({
            'AI_LLM_API_KEY': 'k' * 24,
            'AI_LLM_ENDPOINT': 'http://evil.example.com/v1'})
    with pytest.raises(LLMError):
        OpenAICompatibleLLMProvider({
            'AI_LLM_API_KEY': 'k' * 24,
            'AI_LLM_ENDPOINT': 'ftp://api.openai.com/v1'})
    with pytest.raises(LLMError):
        OpenAICompatibleLLMProvider({
            'AI_LLM_API_KEY': 'k' * 24, 'AI_LLM_TIMEOUT_SECONDS': '999'})
    with pytest.raises(LLMError):
        OpenAICompatibleLLMProvider({
            'AI_LLM_API_KEY': 'k' * 24, 'AI_LLM_TEMPERATURE': '42'})
    loopback = OpenAICompatibleLLMProvider({
        'AI_LLM_API_KEY': 'k' * 24,
        'AI_LLM_ENDPOINT': 'http://127.0.0.1:11434/v1/chat/completions'})
    assert loopback.available() is True


def test_openai_compatible_api_key_from_file(tmp_path, monkeypatch):
    # Windows path/locking quirks: change into tmp_path so a relative path
    # in the env proves the file loader resolves paths correctly.
    key_file = tmp_path / 'key.txt'
    key_file.write_text('file-loaded-key-123456', encoding='utf-8')
    provider = OpenAICompatibleLLMProvider({'AI_LLM_API_KEY_FILE': str(key_file)})
    assert provider.api_key == 'file-loaded-key-123456'
    monkeypatch.chdir(tmp_path)
    relative = OpenAICompatibleLLMProvider({'AI_LLM_API_KEY_FILE': 'key.txt'})
    assert relative.api_key == 'file-loaded-key-123456'
    with pytest.raises(LLMError):
        OpenAICompatibleLLMProvider(
            {'AI_LLM_API_KEY_FILE': str(tmp_path / 'absent.txt')})


def test_openai_compatible_json_extraction_from_prose():
    extract = OpenAICompatibleLLMProvider._extract_json_object
    assert extract('{"a": 1}') == {'a': 1}
    assert extract('```json\n{"a": 2}\n```') == {'a': 2}
    assert extract('Sure: {"a": 3} done') == {'a': 3}
    with pytest.raises(LLMError):
        extract('no json at all')
    with pytest.raises(LLMError):
        extract('[1, 2, 3]')


def test_openai_compatible_network_failures_are_controlled(monkeypatch):
    import urllib.error
    provider = OpenAICompatibleLLMProvider({'AI_LLM_API_KEY': 'k' * 24})

    def raise_url_error(request, timeout):
        raise urllib.error.URLError('connection refused')

    monkeypatch.setattr('urllib.request.urlopen', raise_url_error)
    with pytest.raises(LLMError, match='unreachable'):
        provider.complete_json('system', 'user')


def test_openai_compatible_oversized_response_rejected(monkeypatch):
    import io

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return b'x' * (MAX_RESPONSE_CHARS + 10)

    provider = OpenAICompatibleLLMProvider({'AI_LLM_API_KEY': 'k' * 24})
    monkeypatch.setattr('urllib.request.urlopen',
                        lambda request, timeout: FakeResponse())
    with pytest.raises(LLMError, match='maximum size'):
        provider.complete_json('system', 'user')


def test_openai_compatible_never_logs_credentials(monkeypatch, caplog):
    import io

    captured = {}

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    body = json.dumps({'choices': [{'message': {'content': '{"ok": true}'}}]})
    fake = FakeResponse(body.encode('utf-8'))

    def fake_urlopen(request, timeout):
        captured['headers'] = dict(request.header_items())
        return fake

    provider = OpenAICompatibleLLMProvider({'AI_LLM_API_KEY': 'sekrit-value-123'})
    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    result = provider.complete_json('system', 'user')
    assert result == {'ok': True}
    # The key is sent exactly once as a bearer header, never logged.
    headers = {key.lower(): value for key, value in captured['headers'].items()}
    assert headers['authorization'] == 'Bearer sekrit-value-123'
    assert 'sekrit-value-123' not in caplog.text


def test_llm_factory_env_driven_and_safe_default():
    assert isinstance(make_llm_provider({}), DisabledLLMProvider)
    assert isinstance(make_llm_provider({'AI_LLM_PROVIDER': 'mock'}),
                      MockLLMProvider)
    with pytest.raises(LLMError):
        make_llm_provider({'AI_LLM_PROVIDER': 'not-a-provider'})
