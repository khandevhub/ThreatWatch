"""Phase 4A vector store tests: persistence, validation, deterministic search."""
import os

import pytest

from vector_store import (
    DEFAULT_SEARCH_LIMIT,
    MAX_SEARCH_LIMIT,
    VectorStore,
    VectorStoreError,
)

DIM = 8


def _vector(seed, dim=DIM):
    vector = [0.0] * dim
    vector[seed % dim] = 1.0
    return vector


@pytest.fixture()
def store(tmp_path):
    return VectorStore(db_file=str(tmp_path / 'knowledge.sqlite'))


def _chunk(chunk_id, vector, document_id=None, content='chunk content',
           document_type='detection_rule', source='unit-test', metadata=None):
    return {
        'chunk_id': chunk_id,
        'document_id': document_id or chunk_id.split('#')[0],
        'document_type': document_type,
        'source': source,
        'content': content,
        'embedding': vector,
        'metadata': metadata or {},
    }


# -- insert / get / count ------------------------------------------------------

def test_insert_and_get_roundtrip(store):
    store.set_embedding_model('hashing-v1')
    store.upsert('doc#000', _vector(1), 'doc', 'brute force guidance',
                 'detection_rule', 'unit-test',
                 metadata={'rule_id': 'TW-001', 'title': 'Brute Force'})
    record = store.get('doc#000')
    assert record['chunk_id'] == 'doc#000'
    assert record['document_type'] == 'detection_rule'
    assert record['title'] == 'Brute Force'
    assert record['content_sha256']
    assert store.count() == 1
    assert store.count(filters={'document_type': 'detection_rule'}) == 1
    assert store.count(filters={'document_type': 'threat_intelligence'}) == 0


def test_update_overwrites_same_chunk_id(store):
    store.upsert('doc#000', _vector(0), 'doc', 'original content',
                 'detection_rule', 'unit-test')
    store.upsert('doc#000', _vector(1), 'doc', 'updated content',
                 'detection_rule', 'unit-test')
    assert store.count() == 1
    assert store.get('doc#000')['content'] == 'updated content'


def test_get_missing_returns_none(store):
    assert store.get('nope#000') is None


# -- delete --------------------------------------------------------------------

def test_delete_chunk(store):
    store.upsert_many([
        _chunk('a#000', _vector(0)), _chunk('a#001', _vector(1)),
    ])
    assert store.delete('a#000') is True
    assert store.delete('a#000') is False
    assert store.get('a#000') is None
    assert store.count() == 1


def test_delete_document_removes_all_chunks(store):
    store.upsert_many([
        _chunk('doc#000', _vector(0)), _chunk('doc#001', _vector(1)),
        _chunk('other#000', _vector(2)),
    ])
    removed = store.delete_document('doc')
    assert removed == 2
    assert store.count() == 1
    assert store.get_document_chunks('doc') == []


# -- search --------------------------------------------------------------------

def test_search_orders_by_score_then_chunk_id(store):
    store.upsert_many([
        _chunk('b#000', _vector(1)), _chunk('a#000', _vector(1)),
        _chunk('c#000', _vector(5)),
    ])
    results = store.search(_vector(1), limit=10)
    assert [r['chunk_id'] for r in results['results']] == ['a#000', 'b#000', 'c#000']
    assert results['results'][0]['score'] == pytest.approx(1.0)
    assert results['results'][0]['embedding_model'] == 'unknown'
    assert 'embedding' not in results['results'][0]


def test_search_empty_store_returns_empty_results(store):
    results = store.search(_vector(0), limit=5)
    assert results['total'] == 0
    assert results['results'] == []


def test_search_pagination_and_limits(store):
    store.upsert_many([_chunk(f'doc#{i:03d}', _vector(i)) for i in range(5)])
    page_one = store.search(_vector(0), limit=2, offset=0)
    page_two = store.search(_vector(0), limit=2, offset=2)
    assert len(page_one['results']) == 2
    assert len(page_two['results']) == 2
    assert page_one['results'][0]['chunk_id'] != page_two['results'][0]['chunk_id']
    assert page_one['total'] == 5
    with pytest.raises(VectorStoreError):
        store.search(_vector(0), limit=0)
    with pytest.raises(VectorStoreError):
        store.search(_vector(0), limit=MAX_SEARCH_LIMIT + 1)
    with pytest.raises(VectorStoreError):
        store.search(_vector(0), limit=DEFAULT_SEARCH_LIMIT, offset=-1)
    with pytest.raises(VectorStoreError):
        store.search(_vector(0), limit='not-a-number')


def test_search_mismatched_query_dimensions_rejected(store):
    store.upsert('doc#000', _vector(0), 'doc', 'content', 'detection_rule', 'unit-test')
    with pytest.raises(VectorStoreError):
        store.search([0.1] * (DIM + 8))


# -- dimension validation ------------------------------------------------------

def test_upsert_rejects_bad_embeddings(store):
    with pytest.raises(VectorStoreError):
        store.upsert('x#000', [], 'x', 'content', 'detection_rule', 'unit-test')
    with pytest.raises(VectorStoreError):
        store.upsert('x#000', ['a', 'b'], 'x', 'content', 'detection_rule', 'unit-test')
    with pytest.raises(VectorStoreError):
        store.upsert('x#000', [float('nan')] * DIM, 'x', 'content',
                     'detection_rule', 'unit-test')


def test_store_locks_dimensions_on_first_write(store):
    store.upsert('doc#000', _vector(0), 'doc', 'content', 'detection_rule', 'unit-test')
    with pytest.raises(VectorStoreError, match='dimensions'):
        store.upsert('other#000', [0.0] * (DIM * 2), 'other', 'content',
                     'detection_rule', 'unit-test')


# -- metadata filtering --------------------------------------------------------

def test_metadata_filters_document_type_source(store):
    store.upsert('r#000', _vector(0), 'r', 'rule text', 'detection_rule', 'feed-a')
    store.upsert('g#000', _vector(0), 'g', 'guide text', 'investigation_guide', 'feed-b')
    assert store.count(filters={'document_type': 'detection_rule'}) == 1
    assert store.count(filters={'source': 'feed-b'}) == 1
    combined = store.search(_vector(0), limit=10,
                            filters={'document_type': 'detection_rule',
                                     'source': 'feed-a'})
    assert [r['chunk_id'] for r in combined['results']] == ['r#000']


def test_metadata_filters_technique_rule_alert_time(store):
    store.upsert('r#000', _vector(0), 'r', 'spray rule', 'detection_rule', 's',
                 metadata={'rule_id': 'TW-004', 'alert_id': 7,
                           'mitre_techniques': ['T1110.003'],
                           'timestamp': '2026-03-01T00:00:00Z'})
    assert store.count(filters={'technique': 'T1110.003'}) == 1
    # Quote-delimited: the sub-technique never matches its parent.
    assert store.count(filters={'technique': 'T1110'}) == 0
    assert store.count(filters={'rule_id': 'TW-004'}) == 1
    assert store.count(filters={'rule_id': 'TW-999'}) == 0
    assert store.count(filters={'alert_id': 7}) == 1
    assert store.count(filters={'alert_id': 8}) == 0
    assert store.count(filters={'time_from': '2026-01-01'}) == 1
    assert store.count(filters={'time_to': '2025-12-31'}) == 0
    assert store.count(filters={'time_from': '2026-01-01',
                                'time_to': '2026-12-31'}) == 1


def test_unknown_filters_fail_closed(store):
    with pytest.raises(VectorStoreError, match='unknown filter'):
        store.count(filters={'evil_column': 'x'})
    with pytest.raises(VectorStoreError):
        store.search(_vector(0), filters={'technique': 'DROP TABLE x'})
    with pytest.raises(VectorStoreError):
        store.count(filters='not-a-mapping')


# -- persistence ---------------------------------------------------------------

def test_store_persists_between_instances(tmp_path):
    db_file = str(tmp_path / 'persist.sqlite')
    store = VectorStore(db_file=db_file)
    store.set_embedding_model('hashing-v1')
    store.upsert('doc#000', _vector(0), 'doc', 'persisted content',
                 'detection_rule', 'unit-test')
    reopened = VectorStore(db_file=db_file)
    assert reopened.count() == 1
    record = reopened.get('doc#000')
    assert record['content'] == 'persisted content'
    assert reopened.stats()['embedding_model'] == 'hashing-v1'


# -- input validation ----------------------------------------------------------

def test_upsert_rejects_invalid_identifiers_and_metadata(store):
    with pytest.raises(VectorStoreError):
        store.upsert('', _vector(0), 'doc', 'content', 'detection_rule', 's')
    with pytest.raises(VectorStoreError):
        store.upsert('doc#000', _vector(0), 'doc', 'content',
                     'Bad Type!', 'source')
    with pytest.raises(VectorStoreError):
        store.upsert('doc#000', _vector(0), 'doc', 'content',
                     'detection_rule', 'bad source; DROP')
    with pytest.raises(VectorStoreError):
        store.upsert('doc#000', _vector(0), 'doc', 'content',
                     'detection_rule', 's', metadata={'bad key!': 'x'})
    with pytest.raises(VectorStoreError):
        store.upsert('doc#000', _vector(0), 'doc', 'content',
                     'detection_rule', 's', metadata={'k': ['nested']})


def test_upsert_rejects_oversized_content(store):
    with pytest.raises(VectorStoreError):
        store.upsert('doc#000', _vector(0), 'doc', 'x' * 40_000,
                     'detection_rule', 's')


def test_stats_shape(store):
    store.upsert('r#000', _vector(0), 'r', 'content', 'detection_rule', 's')
    stats = store.stats()
    assert stats['chunks'] == 1
    assert stats['documents'] == 1
    assert stats['by_document_type'] == {'detection_rule': 1}
    assert stats['schema_version'] == 1
