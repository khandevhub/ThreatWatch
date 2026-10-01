"""Phase 4K + API tests: AI-assisted hunting and the AI copilot endpoints."""
import json
import sqlite3

import pytest

import detector
import ai_hunting
import ai_investigation
from ai_hunting import (
    AIHuntError,
    build_hunt_query,
    execute_ai_hunt,
    validate_ai_hunt_summary,
)
from detector import process_event
from embeddings import HashingEmbeddingProvider
from knowledge import KnowledgeIngester
from llm_provider import DisabledLLMProvider, MockLLMProvider
from vector_store import VectorStore

TOKEN = 'phase4-ai-api-' + 'x' * 40
AUTH = {'Authorization': 'Bearer ' + TOKEN}


class TranslateMock:
    """Deterministic translator: NL -> structured filters (mock LLM)."""

    def __init__(self, payload=None):
        self.payload = payload

    def available(self):
        return True

    def describe(self):
        return {'provider': 'mock', 'model': 'translate-mock'}

    def complete_json(self, system_prompt, user_prompt, manifest=None, **kwargs):
        if manifest and manifest.get('purpose') == 'hunt_summary':
            return {'summary': 'Repeated authentication failures from one '
                               'source; consistent with credential attacks.',
                    'observations': ['single source', 'three accounts'],
                    'confidence': 0.8}
        if self.payload is not None:
            if isinstance(self.payload, Exception):
                raise self.payload
            return self.payload
        text = user_prompt.lower()
        filters = {}
        if '203.0.113' in text:
            filters['src_ip'] = '203.0.113.8'
        if 'auth' in text or 'login' in text:
            filters['event_type'] = 'auth_failed'
        return {'filters': filters, 'limit': 50,
                'explanation': 'matched the request entities'}


@pytest.fixture()
def environment(tmp_path, monkeypatch):
    dbfile = tmp_path / 'soc.sqlite'
    knowledge_db = tmp_path / 'knowledge.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    detector.DB = str(dbfile)
    detector.reload_soc_components({})
    detector.init_db(str(dbfile))
    store = VectorStore(db_file=str(knowledge_db))
    KnowledgeIngester(store, HashingEmbeddingProvider()).ingest_detection_rules()
    for user in ('alice', 'bob', 'carol'):
        process_event({'event_id': f'hunt4-{user}', 'type': 'auth_failed',
                       'src': '203.0.113.8', 'user': user})
    with sqlite3.connect(str(dbfile)) as connection:
        alert_id = connection.execute(
            'SELECT id FROM alerts ORDER BY id DESC LIMIT 1').fetchone()[0]
    from app import create_app
    application = create_app({
        'DB_FILE': str(dbfile),
        'KNOWLEDGE_DB_FILE': str(knowledge_db),
        'INGEST_TOKEN': TOKEN,
        'TESTING': True,
    })
    return {
        'db_file': str(dbfile), 'knowledge_db': str(knowledge_db),
        'alert_id': alert_id, 'app': application,
    }


# -- 4K: query translation and validation -----------------------------------------

def test_nl_to_structured_hunt_query():
    query = build_hunt_query(
        'show authentication failures from 203.0.113.8', TranslateMock())
    assert query['filters'] == {'src_ip': '203.0.113.8',
                                'event_type': 'auth_failed'}
    assert 1 <= query['limit'] <= 500
    assert query['explanation']


@pytest.mark.parametrize('payload,reason', [
    ({'filters': {'sql': 'SELECT 1'}}, 'unsupported_filter'),
    ({'filters': {'user': "admin'; DROP TABLE events--"}},
     'invalid_filter_value'),
    ({'filters': {'time_from': 'yesterday'}}, 'invalid_filter_value'),
    ({'filters': {'technique': 'T9999; --'}}, 'invalid_filter_value'),
    ({'filters': 'DROP TABLE x'}, 'invalid_ai_response'),
    ({'filters': {'src_ip': '203.0.113.8'}, 'limit': 100000},
     'invalid_ai_response'),
    ({'filters': {'src_ip': '203.0.113.8'}, 'limit': 'lots'},
     'invalid_ai_response'),
])
def test_model_inventions_are_rejected(payload, reason):
    with pytest.raises(AIHuntError) as excinfo:
        build_hunt_query('hunt request', TranslateMock(payload))
    assert excinfo.value.reason == reason


def test_exact_filter_sql_injection_is_parameterized_safe(environment):
    # Exact-match values are opaque parameterized data in the hunting layer:
    # hostile values must execute safely and match nothing, never error out
    # into an unfiltered query.
    from hunting import hunt
    results = hunt({'event_type': "x'; DROP TABLE events--"},
                   db_file=environment['db_file'])
    assert results['total'] == 0
    with sqlite3.connect(environment['db_file']) as connection:
        remaining = connection.execute(
            'SELECT COUNT(*) FROM events').fetchone()[0]
    assert remaining == 3  # table survived; injection was a no-op


def test_ai_hunt_requires_available_provider():
    with pytest.raises(AIHuntError) as excinfo:
        build_hunt_query('hunt', DisabledLLMProvider())
    assert excinfo.value.reason == 'ai_provider_disabled'


def test_ai_hunt_oversized_and_empty_requests_rejected():
    with pytest.raises(AIHuntError):
        build_hunt_query('x' * 600, TranslateMock())
    with pytest.raises(AIHuntError):
        build_hunt_query('   ', TranslateMock())


def test_execute_ai_hunt_end_to_end_with_mock(environment):
    outcome = execute_ai_hunt(
        'authentication failures from 203.0.113.8',
        llm_provider=TranslateMock(), db_file=environment['db_file'])
    assert outcome['status'] == 'ok'
    assert outcome['results']['total'] == 3
    assert outcome['summary']['status'] == 'ok'
    assert outcome['summary']['summary']
    assert 0.0 <= outcome['summary']['confidence'] <= 1.0
    assert outcome['advisory_only'] is True


def test_execute_ai_hunt_summary_failure_keeps_results(environment):
    class SummaryFails(TranslateMock):
        def complete_json(self, system_prompt, user_prompt, manifest=None, **kwargs):
            if manifest and manifest.get('purpose') == 'hunt_summary':
                raise RuntimeError('model unavailable')
            return super().complete_json(system_prompt, user_prompt,
                                         manifest, **kwargs)

    outcome = execute_ai_hunt('authentication failures from 203.0.113.8',
                              llm_provider=SummaryFails(),
                              db_file=environment['db_file'])
    assert outcome['results']['total'] == 3
    assert outcome['summary']['status'] == 'unavailable'


def test_ai_hunt_summary_validation():
    good = validate_ai_hunt_summary(
        {'summary': 'Three failures.', 'observations': ['same source'],
         'confidence': 0.9})
    assert good['status'] if False else good['confidence'] == 0.9
    for bad in ('string', {}, {'summary': ''},
                {'summary': 's', 'observations': ['x' * 400]},
                {'summary': 's', 'confidence': 7},
                {'summary': 's', 'observations': 'not-a-list'}):
        with pytest.raises(AIHuntError):
            validate_ai_hunt_summary(bad)


# -- API endpoints -----------------------------------------------------------------

def test_api_ai_investigation_disabled_state(environment):
    client = environment['app'].test_client()
    response = client.get(
        f"/api/alerts/{environment['alert_id']}/ai-investigation")
    assert response.status_code == 200
    body = response.get_json()
    assert body['status'] == 'disabled'
    assert body['reason'] == 'ai_provider_disabled'
    assert body['ai_schema_version'] == 1


def test_api_ai_investigation_404(environment):
    client = environment['app'].test_client()
    assert client.get('/api/alerts/99999/ai-investigation').status_code == 404
    assert client.get('/api/alerts/99999/ai-report').status_code == 404


def test_api_ai_investigation_with_mock_provider(environment, monkeypatch):
    monkeypatch.setattr(ai_investigation, 'make_llm_provider',
                        lambda environ=None: MockLLMProvider())
    client = environment['app'].test_client()
    response = client.get(
        f"/api/alerts/{environment['alert_id']}/ai-investigation")
    body = response.get_json()
    assert body['status'] == 'ok'
    assert body['response']['summary']
    assert body['advisory_only'] is True


def test_api_ai_report_works_with_ai_disabled(environment):
    client = environment['app'].test_client()
    response = client.get(f"/api/alerts/{environment['alert_id']}/ai-report")
    assert response.status_code == 200
    report = response.get_json()
    assert report['ai_status'] == 'disabled'
    assert report['alert_overview']['alert_id'] == environment['alert_id']


def test_api_ai_endpoints_require_bearer_for_writes(environment):
    client = environment['app'].test_client()
    assert client.post(
        f"/api/alerts/{environment['alert_id']}/ai-investigation",
    ).status_code == 401
    assert client.post(
        f"/api/alerts/{environment['alert_id']}/ai-investigation",
        headers={'Authorization': 'Bearer wrong'}).status_code == 401
    assert client.post('/api/hunt/ai', json={'query': 'x'}).status_code == 401
    # Correct token passes authentication (then fails on disabled AI -> 400).
    response = client.post('/api/hunt/ai', headers=AUTH,
                           json={'query': 'failed logins'})
    assert response.status_code == 400
    assert response.get_json()['error'] == 'ai_provider_disabled'


def test_api_ai_hunt_validation_errors(environment):
    client = environment['app'].test_client()
    assert client.post('/api/hunt/ai', headers=AUTH,
                       json={}).status_code == 400
    assert client.post('/api/hunt/ai', headers=AUTH,
                       json={'query': ''}).status_code == 400
    assert client.post('/api/hunt/ai', headers=AUTH,
                       json={'query': 'x' * 600}).status_code == 400
    assert client.post('/api/hunt/ai', headers=AUTH, data='not json',
                       content_type='application/json').status_code == 400


def test_api_ai_hunt_with_mock_provider(environment, monkeypatch):
    monkeypatch.setattr(ai_hunting, 'make_llm_provider',
                        lambda environ=None: TranslateMock())
    client = environment['app'].test_client()
    response = client.post('/api/hunt/ai', headers=AUTH,
                           json={'query': 'authentication failures from 203.0.113.8'})
    assert response.status_code == 200
    body = response.get_json()
    assert body['query']['filters']['src_ip'] == '203.0.113.8'
    assert body['results']['total'] == 3


def test_api_ai_investigation_internal_failure_is_503(environment, monkeypatch):
    import app as app_module
    client = environment['app'].test_client()

    class ExplodingEngine:
        def __init__(self, *args, **kwargs):
            pass

        def investigate(self, alert_id):
            raise RuntimeError('unexpected')

    # app.py binds the name directly, so patch it in the app module namespace.
    monkeypatch.setattr(app_module, 'AIInvestigationEngine', ExplodingEngine)
    response = client.get(
        f"/api/alerts/{environment['alert_id']}/ai-investigation")
    assert response.status_code == 503
    assert response.get_json()['status'] == 'unavailable'


def test_api_never_exposes_provider_credentials(environment):
    client = environment['app'].test_client()
    for path in (f"/api/alerts/{environment['alert_id']}/ai-investigation",
                 f"/api/alerts/{environment['alert_id']}/ai-report"):
        body = json.dumps(client.get(path).get_json())
        assert 'sekrit' not in body
        assert 'api_key' not in body
        assert 'bearer ' not in body.lower().replace('bearer ***', '')
