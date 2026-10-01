"""Phase 4C knowledge ingestion tests: sources, chunking, idempotence, safety."""
import pytest

from embeddings import HashingEmbeddingProvider, MockEmbeddingProvider
from knowledge import (
    CHUNK_MAX_CHARS,
    DOCUMENT_TYPE_DETECTION_RULE,
    DOCUMENT_TYPE_INVESTIGATION_GUIDE,
    DOCUMENT_TYPE_MITRE_TECHNIQUE,
    DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
    KnowledgeError,
    KnowledgeIngester,
    MAX_CHUNKS_PER_DOCUMENT,
    build_document_chunks,
    chunk_text,
)
from vector_store import VectorStore, VectorStoreError


@pytest.fixture()
def ingester(tmp_path):
    store = VectorStore(db_file=str(tmp_path / 'knowledge.sqlite'))
    return KnowledgeIngester(store, HashingEmbeddingProvider(),
                             db_file=str(tmp_path / 'soc.sqlite')), store


# -- chunking ------------------------------------------------------------------

def test_chunk_text_deterministic():
    text = ('Paragraph one about brute force detection. ' * 20) + '\n\n' + (
        'Second paragraph about powershell logging. ' * 20)
    assert chunk_text(text) == chunk_text(text)


def test_chunk_text_respects_maximum_size():
    text = 'word ' * 2000
    chunks = chunk_text(text)
    assert 0 < len(chunks) <= MAX_CHUNKS_PER_DOCUMENT
    assert all(len(chunk) <= CHUNK_MAX_CHARS for chunk in chunks)


def test_chunk_text_overlap_carries_context():
    long_sentence = ('authentication failure analysis ' * 120).strip()
    chunks = chunk_text(long_sentence, max_chars=400, overlap=80)
    assert len(chunks) > 1
    # Hard-cut overlap repeats the tail of the previous chunk.
    assert chunks[1].startswith(chunks[0][-80:])


def test_chunk_text_empty_and_tiny_documents():
    assert chunk_text('') == []
    assert chunk_text('   \n\n  ') == []
    tiny = chunk_text('single short note')
    assert tiny == ['single short note']


def test_chunk_text_parameter_validation():
    with pytest.raises(KnowledgeError):
        chunk_text('x', max_chars=50)
    with pytest.raises(KnowledgeError):
        chunk_text('x', max_chars=400, overlap=400)


# -- document chunk building ---------------------------------------------------

def test_build_document_chunks_stable_ids_and_metadata():
    document = {
        'document_id': 'detection_rule:tw-001-brute-force',
        'document_type': DOCUMENT_TYPE_DETECTION_RULE,
        'source': 'detection_rules',
        'title': 'TW-001 Brute Force',
        'content': 'Detects repeated authentication failures from one source.',
        'metadata': {'rule_id': 'TW-001'},
    }
    first = build_document_chunks(document)
    second = build_document_chunks(document)
    assert [c['chunk_id'] for c in first['chunks']] == \
        [c['chunk_id'] for c in second['chunks']]
    chunk = first['chunks'][0]
    assert chunk['metadata']['rule_id'] == 'TW-001'
    assert chunk['metadata']['document_type'] == DOCUMENT_TYPE_DETECTION_RULE
    assert chunk['metadata']['content_hash']
    assert chunk['metadata']['classification'] == 'internal'
    assert chunk['metadata']['version'] == 1


def test_build_document_chunks_redacts_secrets():
    document = {
        'document_id': 'project_documentation:notes',
        'document_type': DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
        'source': 'project_docs',
        'title': 'Notes',
        'content': 'Configure with api_key=supersecret123 and Bearer tok.en.value.',
    }
    prepared = build_document_chunks(document)
    joined = ' '.join(chunk['content'] for chunk in prepared['chunks'])
    assert 'supersecret123' not in joined
    assert 'tok.en.value' not in joined
    assert '***REDACTED***' in joined


def test_build_document_chunks_requires_fields():
    with pytest.raises(KnowledgeError):
        build_document_chunks({'document_id': 'x'})
    with pytest.raises(KnowledgeError):
        build_document_chunks({
            'document_id': 'x', 'document_type': 'not_a_type',
            'source': 's', 'title': 't', 'content': 'c'})


# -- ingestion sources ----------------------------------------------------------

def test_ingest_detection_rules_indexes_all_rules(ingester):
    ing, store = ingester
    results = ing.ingest_detection_rules()
    assert len(results) == 10
    assert all(r['chunks'] > 0 for r in results)
    assert store.count(filters={'document_type': DOCUMENT_TYPE_DETECTION_RULE}) > 0
    assert all(r['document_id'].startswith('detection_rule:') for r in results)


def test_ingest_mitre_techniques_covers_project_mappings(ingester):
    ing, store = ingester
    results = ing.ingest_mitre_techniques()
    techniques = {r['document_id'] for r in results}
    assert 'mitre_technique:t1110.003-password-spraying' in techniques
    assert 'mitre_technique:t1110-brute-force' in techniques
    assert len(results) == 12  # every mapping in ATTACK_TECHNIQUE_NAMES
    # count() counts chunks, not documents: compare against chunk totals.
    assert store.count(
        filters={'document_type': DOCUMENT_TYPE_MITRE_TECHNIQUE}) == sum(
        r['chunks'] for r in results)


def test_ingest_threat_intel_structural_and_safe(ingester, tmp_path):
    ing, store = ingester
    csv_file = tmp_path / 'intel.csv'
    csv_file.write_text(
        'indicator,tag,confidence,source\n'
        '203.0.113.66,known_scanner,0.9,unit-feed\n'
        'evil.example.com,phishing,0.8,unit-feed\n',
        encoding='utf-8')
    result = ing.ingest_threat_intel(str(csv_file))
    assert result['loaded'] == 2
    assert len(result['documents']) == 1  # grouped by source
    chunks = store.get_document_chunks(result['documents'][0]['document_id'])
    joined = ' '.join(chunk['content'] for chunk in chunks)
    assert '203.0.113.66' in joined
    assert 'evil.example.com' in joined


def test_ingest_investigation_guides(ingester):
    ing, store = ingester
    results = ing.ingest_investigation_guides()
    assert len(results) == 11  # 10 rule guides + 1 lifecycle guide
    assert store.count(
        filters={'document_type': DOCUMENT_TYPE_INVESTIGATION_GUIDE}) == sum(
        r['chunks'] for r in results)


def test_ingest_project_docs_allowlist_only(ingester):
    ing, store = ingester
    results = ing.ingest_project_docs(root='.')
    document_ids = {r['document_id'] for r in results}
    # Only the fixed allowlist can ever appear: no caller-supplied file path
    # is accepted by the ingestion API.
    assert document_ids <= {
        'project_documentation:readme.md', 'project_documentation:license.txt'}
    assert 'project_documentation:readme.md' in document_ids
    # A base directory without the allowlist files simply yields nothing.
    assert ing.ingest_project_docs(root='..') == []


def test_ingest_historical_incidents_requires_soc_database(ingester):
    ing, store = ingester
    # No SOC database at all -> skip gracefully (empty result, no raise).
    assert ing.ingest_historical_incidents(db_file='missing.sqlite') == []


def test_ingest_historical_incidents_uses_resolved_alerts(ingester, tmp_path):
    ing, store = ingester
    import sqlite3
    soc_db = tmp_path / 'soc.sqlite'
    with sqlite3.connect(soc_db) as connection:
        connection.execute(
            "CREATE TABLE alerts (id INTEGER PRIMARY KEY, time TEXT, rule TEXT, "
            "severity TEXT, rule_id TEXT, correlation_id TEXT, "
            "deterministic_risk_score INTEGER, risk_band TEXT, "
            "investigation_status TEXT DEFAULT 'new')")
        connection.execute(
            "INSERT INTO alerts (id, time, rule, severity, rule_id, "
            "correlation_id, deterministic_risk_score, risk_band, "
            "investigation_status) VALUES (1, '2026-01-01T00:00:00Z', "
            "'PASSWORD_SPRAYING', 'HIGH', 'TW-004', 'corr-1', 72, 'high', "
            "'resolved')")
        connection.execute(
            "INSERT INTO alerts (id, time, rule, severity, rule_id, "
            "correlation_id, deterministic_risk_score, risk_band, "
            "investigation_status) VALUES (2, '2026-01-02T00:00:00Z', "
            "'PORT_SCAN', 'MEDIUM', 'TW-002', NULL, 30, 'medium', 'new')")
    results = ing.ingest_historical_incidents(db_file=str(soc_db))
    assert len(results) == 1  # only the resolved alert
    chunks = store.get_document_chunks(results[0]['document_id'])
    joined = ' '.join(chunk['content'] for chunk in chunks)
    assert 'TW-004' in joined
    assert results[0]['document_id'] == 'historical_incident:alert-1'


# -- idempotence and reindexing ---------------------------------------------------

def test_duplicate_ingestion_does_not_duplicate_chunks(ingester):
    ing, store = ingester
    first = ing.ingest_detection_rules()
    count_after_first = store.count()
    second = ing.ingest_detection_rules()
    assert store.count() == count_after_first
    assert [r['content_hash'] for r in first] == [r['content_hash'] for r in second]


def test_changed_document_replaces_its_chunks(ingester):
    ing, store = ingester
    base = {
        'document_id': 'project_documentation:manual',
        'document_type': DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
        'source': 'project_docs',
        'title': 'Manual',
        'content': '\n\n'.join(f'Paragraph {n} with operational guidance text.'
                               for n in range(12)),
    }
    ing._index_document(base)
    chunks_before = len(store.get_document_chunks(base['document_id']))
    assert chunks_before > 1
    changed = dict(base, content='One short replacement paragraph.')
    ing._index_document(changed)
    chunks_after = store.get_document_chunks(base['document_id'])
    assert len(chunks_after) == 1
    assert 'replacement' in chunks_after[0]['content']


def test_secret_is_redacted_before_embedding(ingester):
    ing, store = ingester
    document = {
        'document_id': 'project_documentation:leaky',
        'document_type': DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
        'source': 'project_docs',
        'title': 'Leaky',
        'content': 'The token is password=hunter2 in configuration.',
    }
    ing._index_document(document)
    joined = ' '.join(chunk['content']
                      for chunk in store.get_document_chunks(document['document_id']))
    assert 'hunter2' not in joined
    assert '***REDACTED***' in joined


def test_reindex_all_reports_all_sources(ingester):
    ing, store = ingester
    summary = ing.reindex_all()
    assert set(summary) == {
        'detection_rules', 'mitre_techniques', 'threat_intel',
        'investigation_guides', 'project_docs', 'historical_incidents', 'stats'}
    assert summary['stats']['chunks'] == store.count() > 0


def test_provider_failure_is_explicit(ingester):
    ing, store = ingester

    class FailingProvider(MockEmbeddingProvider):
        def embed_many(self, texts):
            raise RuntimeError('embedding backend offline')

    broken = KnowledgeIngester(store, FailingProvider())
    with pytest.raises(RuntimeError):
        broken.ingest_detection_rules()
    assert store.count() == 0


def test_store_rejects_dimension_change_from_ingester(ingester):
    ing, store = ingester
    ing.ingest_detection_rules()
    swapped = KnowledgeIngester(store, MockEmbeddingProvider(dimensions=8))
    with pytest.raises(VectorStoreError):
        swapped.ingest_detection_rules()
