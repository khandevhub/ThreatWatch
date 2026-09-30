"""End-to-end simulator, durable collector, detector, and dashboard tests."""
import json
import sqlite3
import threading

from collector import SimHandler, TailReader
from database import init_db
from detector import process_event
from event_model import SecurityEvent
from app import create_app
from simulator.append_events import main, write_jsonl
from werkzeug.serving import make_server

TOKEN = 'pipeline-test-' + 'x' * 48


def test_simulator_file_collector_restart_and_dashboard(tmp_path):
    dbfile = tmp_path / 'pipeline.sqlite'
    logfile = tmp_path / 'simulated_logs.jsonl'
    init_db(str(dbfile))
    write_jsonl(str(logfile))

    tail = TailReader(str(logfile), str(dbfile))
    SimHandler(str(logfile), tail=tail, db_file=str(dbfile)).drain()
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 7
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 3

    restarted = TailReader(str(logfile), str(dbfile))
    SimHandler(str(logfile), tail=restarted, db_file=str(dbfile)).drain()
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 7
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 3

    application = create_app({
        'DB_FILE': str(dbfile), 'INGEST_TOKEN': TOKEN, 'TESTING': True,
    })
    client = application.test_client()
    alerts = client.get('/api/alerts').get_json()
    assert {alert['rule'] for alert in alerts} == {
        'BRUTE_FORCE', 'PORT_SCAN', 'TRAFFIC_SPIKE',
    }
    assert client.get('/api/summary').get_json() == {
        'BRUTE_FORCE': 1, 'PORT_SCAN': 1, 'TRAFFIC_SPIKE': 1,
    }
    page = client.get('/')
    assert page.status_code == 200 and b'ThreatWatch' in page.data
    script = client.get('/static/dashboard.js')
    assert script.status_code == 200 and b'details.textContent' in script.data


def test_event_commit_before_cursor_ack_is_idempotent(tmp_path):
    dbfile = tmp_path / 'restart.sqlite'
    logfile = tmp_path / 'events.jsonl'
    logfile.write_text('{"type":"port_scan","src":"9.9.9.9"}\n', encoding='utf-8')
    init_db(str(dbfile))

    first_reader = TailReader(str(logfile), str(dbfile))
    record = first_reader.read_new_lines()[0]
    payload = json.loads(record.raw.decode('utf-8'))
    event = SecurityEvent.from_payload(
        payload, default_source='jsonl', generated_event_id=record.event_id)
    assert process_event(event, db_file=str(dbfile)) is True

    # Simulate a crash after the event/alert transaction but before cursor save.
    restarted = TailReader(str(logfile), str(dbfile))
    SimHandler(str(logfile), tail=restarted, db_file=str(dbfile)).drain()
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 1


def test_malformed_file_record_is_quarantined_without_blocking_next_event(tmp_path):
    dbfile = tmp_path / 'quarantine.sqlite'
    logfile = tmp_path / 'events.jsonl'
    logfile.write_text('not json\n{"type":"port_scan","src":"9.9.9.9"}\n', encoding='utf-8')
    init_db(str(dbfile))

    tail = TailReader(str(logfile), str(dbfile))
    SimHandler(str(logfile), tail=tail, db_file=str(dbfile)).drain()
    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM ingestion_errors').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 1
        offset = connection.execute('SELECT byte_offset FROM file_cursors').fetchone()[0]
    assert offset == logfile.stat().st_size


def test_http_simulator_reaches_authenticated_ingestion_api(tmp_path, monkeypatch):
    monkeypatch.setenv('INGEST_TOKEN', TOKEN)
    dbfile = tmp_path / 'http-e2e.sqlite'
    application = create_app({
        'DB_FILE': str(dbfile), 'INGEST_TOKEN': TOKEN, 'TESTING': False,
    })
    server = make_server('127.0.0.1', 0, application, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = main([
            '--target', 'ingest',
            '--url', f'http://127.0.0.1:{server.server_port}/api/ingest',
        ])
        assert result == 0
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    client = application.test_client()
    assert {row['rule'] for row in client.get('/api/alerts').get_json()} == {
        'BRUTE_FORCE', 'PORT_SCAN', 'TRAFFIC_SPIKE',
    }
    assert client.get('/api/summary').get_json() == {
        'BRUTE_FORCE': 1, 'PORT_SCAN': 1, 'TRAFFIC_SPIKE': 1,
    }
