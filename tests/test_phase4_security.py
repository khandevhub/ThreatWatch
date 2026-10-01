"""Phase 4 security tests: injection-as-data, secrets, traversal, bounds."""
import pytest

from embeddings import HashingEmbeddingProvider
from knowledge import (
    DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
    KnowledgeIngester,
    _stable_document_id,
    build_document_chunks,
)
from retrieval import KnowledgeRetriever, build_rag_context
from vector_store import VectorStore, VectorStoreError


@pytest.fixture()
def indexed(tmp_path):
    store = VectorStore(db_file=str(tmp_path / 'knowledge.sqlite'))
    return store, KnowledgeIngester(store, HashingEmbeddingProvider())


def test_api_keys_and_tokens_are_never_indexed(indexed):
    store, ingester = indexed
    document = {
        'document_id': 'project_documentation:config-notes',
        'document_type': DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
        'source': 'project_docs',
        'title': 'Config notes',
        'content': (
            'Runtime uses INGEST_TOKEN=abcdefghijklmnopqrstuvwx0123456789ABCD '
            'and Authorization: Bearer eyJhbGciOi.secret.value and '
            'JEV_API_KEY=jev-secret-42.'),
    }
    ingester._index_document(document)
    stored = ' '.join(chunk['content']
                      for chunk in store.get_document_chunks(document['document_id']))
    assert 'abcdefghijklmnopqrstuvwx0123456789ABCD' not in stored
    assert 'eyJhbGciOi.secret.value' not in stored
    assert 'jev-secret-42' not in stored


def test_document_ids_are_slugified_no_traversal(indexed):
    # Hostile document names cannot become paths or SQL; IDs are slugs.
    hostile = _stable_document_id(
        DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
        '../../etc/passwd; DROP TABLE users--')
    assert hostile.startswith('project_documentation:')
    slug = hostile.split(':', 1)[1]
    for char in ('/', '\\', '..', ' ', ';', '--'):
        assert char not in slug
    prepared = build_document_chunks({
        'document_id': hostile,
        'document_type': DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
        'source': 'project_docs',
        'title': 'x',
        'content': 'content',
    })
    assert all(c['document_id'] == hostile for c in prepared['chunks'])


def test_ingestion_never_accepts_arbitrary_document_paths(indexed):
    store, ingester = indexed
    # The ingestion API takes structured documents, not filesystem paths:
    # there is no method that reads a caller-supplied file.
    for attribute in dir(ingester):
        if attribute.startswith('ingest_'):
            assert 'path' not in attribute or attribute == 'ingest_threat_intel'
    # The one path-taking source is the local intel CSV; a directory or
    # missing file is skipped, never executed or listed.
    assert ingester.ingest_threat_intel(str(store.db_file) + '.nonexistent')[
        'documents'] == []


def test_metadata_values_are_bounded_and_scalar(indexed):
    store, _ = indexed
    # Oversized scalar metadata is truncated, never stored unbounded.
    store.upsert('x#000', [1.0] * 8, 'x', 'content',
                 'detection_rule', 's', metadata={'blob': 'y' * 2048})
    assert len(store.get('x#000')['metadata']['blob']) <= 512
    with pytest.raises(VectorStoreError):
        store.upsert('x#001', [1.0] * 8, 'x', 'content',
                     'detection_rule', 's',
                     metadata={'nested': {'a': 1}})


def test_retrieval_results_are_never_unbounded(indexed):
    store, _ = indexed
    provider = HashingEmbeddingProvider()
    for index in range(30):
        store.upsert(f'bulk#{index:03d}', provider.embed_text(f'content {index}'),
                     'bulk', f'content {index}', 'detection_rule', 's')
    retriever = KnowledgeRetriever(store, provider)
    out = retriever.retrieve('content', top_k=5)
    assert len(out['results']) == 5
    assert out['total'] == 30
    context = build_rag_context('content', results=out['results'])
    assert len(context['retrieved_documents']) <= 5


def test_store_content_never_contains_secrets_after_full_cycle(tmp_path):
    store = VectorStore(db_file=str(tmp_path / 'knowledge.sqlite'))
    ingester = KnowledgeIngester(store, HashingEmbeddingProvider())
    secret = 'hunter2-super-secret-value'
    ingester._index_document({
        'document_id': 'project_documentation:secrets-probe',
        'document_type': DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
        'source': 'project_docs',
        'title': 'Probe',
        'content': f'password={secret} and private key blocks are masked too.',
    })
    with open(store.db_file, 'rb') as stream:
        raw = stream.read()
    assert secret.encode('utf-8') not in raw
    # Sanity: the store file is valid SQLite with rows present.
    assert store.count() >= 1
