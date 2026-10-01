"""Phase 4D retrieval and RAG-context tests."""
import json

import pytest

from embeddings import (
    DisabledEmbeddingProvider,
    HashingEmbeddingProvider,
    MockEmbeddingProvider,
)
from knowledge import KnowledgeIngester
from retrieval import (
    MAX_CONTEXT_CHARS,
    MAX_QUERY_CHARS,
    MAX_SNIPPET_CHARS,
    MAX_TOP_K,
    KnowledgeRetriever,
    ORIGIN_EVIDENCE,
    ORIGIN_KNOWLEDGE,
    RAG_SCHEMA_VERSION,
    RetrievalError,
    build_rag_context,
)
from vector_store import VectorStore


@pytest.fixture()
def indexed(tmp_path):
    """A knowledge base with rules + MITRE techniques indexed."""
    store = VectorStore(db_file=str(tmp_path / 'knowledge.sqlite'))
    ingester = KnowledgeIngester(store, HashingEmbeddingProvider())
    ingester.ingest_detection_rules()
    ingester.ingest_mitre_techniques()
    return store


# -- retriever construction -----------------------------------------------------

def test_retriever_requires_store_and_provider():
    with pytest.raises(RetrievalError):
        KnowledgeRetriever(None, HashingEmbeddingProvider())
    with pytest.raises(RetrievalError):
        KnowledgeRetriever(VectorStore(db_file=':memory:'), None)


def test_retriever_validates_top_k_bounds():
    with pytest.raises(RetrievalError):
        KnowledgeRetriever(VectorStore(db_file=':memory:'),
                           HashingEmbeddingProvider(), default_top_k=0)
    with pytest.raises(RetrievalError):
        KnowledgeRetriever(VectorStore(db_file=':memory:'),
                           HashingEmbeddingProvider(),
                           max_top_k=MAX_TOP_K + 10)


# -- retrieval behavior ----------------------------------------------------------

def test_retrieve_returns_bounded_results(indexed):
    retriever = KnowledgeRetriever(indexed, HashingEmbeddingProvider())
    out = retriever.retrieve('how to investigate password spraying', top_k=3)
    assert out['total'] > 0
    assert len(out['results']) == 3
    top = out['results'][0]
    assert top['origin'] == ORIGIN_KNOWLEDGE
    assert top['untrusted'] is True
    assert top['score'] is not None
    assert top['content']
    assert top['metadata']
    assert out['retrieval_parameters']['top_k'] == 3
    assert out['retrieval_parameters']['embedding_model'] == 'hashing-v1'
    assert out['retrieval_parameters']['max_top_k'] == MAX_TOP_K


def test_retrieve_is_deterministic_for_equal_scores(tmp_path):
    store = VectorStore(db_file=str(tmp_path / 'ties.sqlite'))
    # Identical vectors produce identical scores; chunk_id breaks ties.
    store.upsert('a#000', [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 'a',
                 'alpha content', 'detection_rule', 'unit-test')
    store.upsert('b#000', [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 'b',
                 'beta content', 'detection_rule', 'unit-test')
    retriever = KnowledgeRetriever(store, MockEmbeddingProvider(dimensions=8))
    first = retriever.retrieve('brute force', top_k=2)
    second = retriever.retrieve('brute force', top_k=2)
    assert [r['chunk_id'] for r in first['results']] == \
        [r['chunk_id'] for r in second['results']]


def test_retrieve_applies_metadata_filters(indexed):
    retriever = KnowledgeRetriever(indexed, HashingEmbeddingProvider())
    out = retriever.retrieve('password spraying', top_k=5,
                             filters={'document_type': 'mitre_technique'})
    assert out['results']
    assert all(r['document_type'] == 'mitre_technique' for r in out['results'])
    out_rules = retriever.retrieve('password spraying', top_k=5,
                                   filters={'document_type': 'detection_rule'})
    assert all(r['document_type'] == 'detection_rule' for r in out_rules['results'])


def test_retrieve_empty_results_for_narrow_filters(indexed):
    retriever = KnowledgeRetriever(indexed, HashingEmbeddingProvider())
    out = retriever.retrieve('password spraying', top_k=5,
                             filters={'technique': 'T9999'})
    assert out['total'] == 0
    assert out['results'] == []


def test_retrieve_validates_query_and_top_k(indexed):
    retriever = KnowledgeRetriever(indexed, HashingEmbeddingProvider())
    with pytest.raises(RetrievalError):
        retriever.retrieve('')
    with pytest.raises(RetrievalError):
        retriever.retrieve('   ')
    with pytest.raises(RetrievalError):
        retriever.retrieve('x' * (MAX_QUERY_CHARS + 1))
    with pytest.raises(RetrievalError):
        retriever.retrieve('valid query', top_k=MAX_TOP_K + 1)
    with pytest.raises(RetrievalError):
        retriever.retrieve('valid query', top_k=0)
    with pytest.raises(RetrievalError):
        retriever.retrieve('valid query', top_k='not-a-number')
    with pytest.raises(RetrievalError):
        retriever.retrieve(12345)


def test_retrieve_fails_closed_when_provider_disabled(indexed):
    retriever = KnowledgeRetriever(indexed, DisabledEmbeddingProvider())
    with pytest.raises(RetrievalError, match='disabled'):
        retriever.retrieve('anything at all')


# -- RAG context builder ----------------------------------------------------------

def _simple_results(count=3):
    return [
        {
            'chunk_id': f'doc#{i:03d}',
            'document_id': f'doc',
            'document_type': 'detection_rule',
            'source': 'detection_rules',
            'title': f'Document {i}',
            'score': 0.9 - i * 0.1,
            'content': f'Knowledge content {i}.',
            'metadata': {'rule_id': 'TW-001'},
            'origin': ORIGIN_KNOWLEDGE,
            'untrusted': True,
        }
        for i in range(count)
    ]


def test_rag_context_structure_and_separation(indexed):
    retriever = KnowledgeRetriever(indexed, HashingEmbeddingProvider())
    evidence = {
        'alert_id': 1,
        'rule_code': 'PASSWORD_SPRAYING',
        'description': 'Auth failures with api_key=sk-live-999 embedded.',
        'entities': {'source_ips': ['203.0.113.50']},
    }
    package = build_rag_context('password spraying investigation',
                                retriever=retriever, evidence=evidence, top_k=3)
    assert package['rag_schema_version'] == RAG_SCHEMA_VERSION
    assert package['query'] == 'password spraying investigation'
    assert sorted(package.keys()) == sorted([
        'rag_schema_version', 'query', 'retrieved_documents', 'evidence',
        'sources', 'metadata', 'retrieval_parameters'])
    # Clear origin separation between knowledge and evidence.
    assert package['evidence']['origin'] == ORIGIN_EVIDENCE
    assert all(doc['origin'] == ORIGIN_KNOWLEDGE
               for doc in package['retrieved_documents'])
    assert all(doc['untrusted'] is True
               for doc in package['retrieved_documents'])
    # No fabricated fields; sources mirror retrieved documents.
    assert len(package['sources']) == len(package['retrieved_documents'])
    assert package['metadata']['generates_answers'] is False
    assert package['metadata']['evidence_included'] is True
    assert 'untrusted' in package['metadata']['usage_note']
    # Secrets in evidence are redacted before serialization.
    serialized = json.dumps(package)
    assert 'sk-live-999' not in serialized
    # JSON-serializable and bounded.
    assert isinstance(serialized, str)
    assert len(serialized) <= MAX_CONTEXT_CHARS * 2


def test_rag_context_without_evidence_omits_section(indexed):
    retriever = KnowledgeRetriever(indexed, HashingEmbeddingProvider())
    package = build_rag_context('brute force guidance', retriever=retriever)
    assert package['evidence'] is None
    assert package['metadata']['evidence_included'] is False


def test_rag_context_bounds_retrieved_context():
    results = [
        dict(_simple_results(1)[0], chunk_id=f'c{i:03d}',
             content='x' * 900, score=0.5)
        for i in range(40)
    ]
    package = build_rag_context('bounded query', results=results)
    used = sum(len(doc['content']) for doc in package['retrieved_documents'])
    assert used <= MAX_CONTEXT_CHARS
    assert package['metadata']['results_truncated_for_context'] is True
    assert package['metadata']['total_matches'] == 40
    assert package['metadata']['retrieved_count'] < 40


def test_rag_context_snippets_are_redacted_and_bounded():
    results = _simple_results(1)
    results[0]['content'] = ('token password=hunter2 here. ' * 100)
    package = build_rag_context('query', results=results)
    content = package['retrieved_documents'][0]['content']
    assert len(content) <= MAX_SNIPPET_CHARS
    assert 'hunter2' not in content
    assert '***REDACTED***' in content


def test_rag_context_rejects_malformed_input(indexed):
    retriever = KnowledgeRetriever(indexed, HashingEmbeddingProvider())
    with pytest.raises(RetrievalError):
        build_rag_context('')
    with pytest.raises(RetrievalError):
        build_rag_context('query', retriever='not-a-retriever')
    with pytest.raises(RetrievalError):
        build_rag_context('query', results='not-a-list')
    with pytest.raises(RetrievalError):
        build_rag_context('query', results=_simple_results(2), evidence='not-a-dict')


def test_rag_context_metadata_includes_bounds():
    package = build_rag_context('query', results=_simple_results(2))
    bounds = package['metadata']['bounds']
    assert bounds['max_query_chars'] == MAX_QUERY_CHARS
    assert bounds['max_top_k'] == MAX_TOP_K
    assert bounds['max_snippet_chars'] == MAX_SNIPPET_CHARS
    assert bounds['max_context_chars'] == MAX_CONTEXT_CHARS
    assert package['retrieval_parameters'] == {'source': 'precomputed'}
