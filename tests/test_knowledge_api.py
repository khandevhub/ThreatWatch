"""Phase 4 API integration tests: knowledge search and investigation context."""
import sqlite3

import pytest

import detector
from detector import process_event

TOKEN = 'phase4-api-test-' + 'x' * 48


@pytest.fixture()
def client(tmp_path, monkeypatch):
    dbfile = tmp_path / 'api4.sqlite'
    knowledge_db = tmp_path / 'knowledge.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    detector.DB = str(dbfile)
    detector.reload_soc_components({})
    detector.init_db(str(dbfile))

    # Index a small knowledge base so the search endpoint has content.
    from embeddings import HashingEmbeddingProvider
    from knowledge import KnowledgeIngester
    from vector_store import VectorStore
    store = VectorStore(db_file=str(knowledge_db))
    ingester = KnowledgeIngester(store, HashingEmbeddingProvider())
    ingester.ingest_detection_rules()

    from app import create_app
    application = create_app({
        'DB_FILE': str(dbfile),
        'KNOWLEDGE_DB_FILE': str(knowledge_db),
        'INGEST_TOKEN': TOKEN,
        'TESTING': True,
    })
    # One realistic spray alert to investigate.
    for user in ('alice', 'bob', 'carol'):
        process_event({'event_id': f'api4-{user}', 'type': 'auth_failed',
                       'src': '203.0.113.7', 'user': user})
    with sqlite3.connect(str(dbfile)) as connection:
        alert_id = connection.execute(
            'SELECT id FROM alerts ORDER BY id DESC LIMIT 1').fetchone()[0]
    with application.test_client() as test_client:
        yield test_client, str(knowledge_db), alert_id


# -- GET /api/knowledge/search ---------------------------------------------------

def test_knowledge_search_returns_results(client):
    http, _, _ = client
    response = http.get('/api/knowledge/search?q=password+spraying&top_k=2')
    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] > 0
    assert len(body['results']) == 2
    top = body['results'][0]
    assert top['document_type'] in ('detection_rule', 'mitre_technique',
                                    'investigation_guide')
    assert top['origin'] == 'knowledge_base'
    assert top['untrusted'] is True
    assert body['retrieval_parameters']['top_k'] == 2


def test_knowledge_search_applies_document_type_filter(client):
    http, _, _ = client
    response = http.get(
        '/api/knowledge/search?q=password+spraying&top_k=3'
        '&document_type=detection_rule')
    assert response.status_code == 200
    assert all(r['document_type'] == 'detection_rule'
               for r in response.get_json()['results'])


def test_knowledge_search_rejects_bad_requests(client):
    http, _, _ = client
    empty = http.get('/api/knowledge/search?q=')
    assert empty.status_code == 400
    assert empty.get_json()['error'] == 'invalid_knowledge_query'
    oversized = http.get('/api/knowledge/search?q=' + 'x' * 600)
    assert oversized.status_code == 400
    bad_top_k = http.get('/api/knowledge/search?q=abc&top_k=9999')
    assert bad_top_k.status_code == 400
    bad_filter = http.get(
        '/api/knowledge/search?q=abc&document_type=DROP%20TABLE%20x')
    assert bad_filter.status_code == 400


def test_knowledge_search_unknown_filter_fails_closed(client):
    http, _, _ = client
    response = http.get('/api/knowledge/search?q=abc&not_a_filter=1')
    assert response.status_code == 400


# -- GET /api/alerts/<id>/investigation?with_knowledge=1 ----------------------------

def test_investigation_with_knowledge_attaches_context(client):
    http, _, alert_id = client
    response = http.get(f'/api/alerts/{alert_id}/investigation?with_knowledge=1')
    assert response.status_code == 200
    package = response.get_json()
    context = package['knowledge_context']
    assert context['status'] == 'ok'
    assert context['retrieved_documents']
    assert all(doc['untrusted'] is True
               for doc in context['retrieved_documents'])
    # Phase 3 sections are untouched.
    for section in ('alert', 'risk', 'evidence', 'timeline', 'mitre',
                    'ai_perspective'):
        assert section in package


def test_investigation_without_flag_has_no_knowledge_context(client):
    http, _, alert_id = client
    response = http.get(f'/api/alerts/{alert_id}/investigation')
    assert response.status_code == 200
    assert 'knowledge_context' not in response.get_json()


def test_investigation_404_preserved_with_knowledge_flag(client):
    http, _, _ = client
    response = http.get('/api/alerts/99999/investigation?with_knowledge=1')
    assert response.status_code == 404


def test_investigation_with_knowledge_never_breaks_package(client, monkeypatch):
    http, knowledge_db, alert_id = client
    # Force retrieval to fail; the investigation package must survive intact.
    import app as app_module

    class ExplodingRetriever:
        def __init__(self, *args, **kwargs):
            raise RuntimeError('retrieval backend offline')

    monkeypatch.setattr(app_module, 'KnowledgeRetriever', ExplodingRetriever)
    response = http.get(f'/api/alerts/{alert_id}/investigation?with_knowledge=1')
    assert response.status_code == 200
    body = response.get_json()
    assert body['knowledge_context'] == {
        'status': 'unavailable', 'reason': 'retrieval_error'}
    assert 'alert' in body and 'evidence' in body
