"""End-to-end SOC pipeline: detection -> intel -> correlation -> risk -> Jev -> alert."""
import sqlite3

import pytest

import detector
from decision import MockDecisionProvider
from detector import process_event


@pytest.fixture()
def pipeline(tmp_path, monkeypatch):
    dbfile = tmp_path / 'e2e.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    detector.DB = str(dbfile)
    detector.reload_soc_components({})
    # Known-malicious source, as if loaded from an offline intel feed.
    # (Set AFTER reload: reload_soc_components rebuilds bad_ips from the feed.)
    detector.bad_ips = {'203.0.113.66': 'known_attacker'}
    detector.init_db(str(dbfile))
    return dbfile


def _db(dbfile):
    connection = sqlite3.connect(str(dbfile))
    connection.row_factory = sqlite3.Row
    return connection


def _soc_alerts(dbfile):
    with _db(dbfile) as connection:
        return connection.execute(
            'SELECT rule, severity, deterministic_risk_score, correlation_id, '
            'jev_priority, jev_status, evidence_json, source_event_ids_json, '
            'rule_id, mitre_techniques_json, investigation_status '
            'FROM alerts ORDER BY id').fetchall()


def test_full_spray_pipeline_with_mock_jev(pipeline, monkeypatch):
    """37-attempt style scenario: spray + brute force + intel + risk + Jev."""
    users = ['alice', 'bob', 'carol', 'dave', 'erica']
    # Inject the mock decision provider as the configured layer.
    monkeypatch.setattr(detector, '_provider', MockDecisionProvider())

    event_ids = []
    for round_no in range(7):                # 35 failures across 5 users
        for user in users:
            event_id = f'e2e-{round_no}-{user}'
            event_ids.append(event_id)
            assert process_event({
                'event_id': event_id, 'type': 'auth_failed',
                'src': '203.0.113.66', 'user': user,
            }) is True

    alerts = _soc_alerts(pipeline)
    assert alerts, 'spray scenario must raise alerts'
    rules = [row['rule'] for row in alerts]
    assert 'PASSWORD_SPRAYING' in rules
    # Brute force merges into the spray correlation group (same source IP):
    # its rule ID must appear in the merged evidence's rule_ids.
    all_evidence = ' '.join(row['evidence_json'] for row in alerts)
    assert 'TW-001' in all_evidence

    spray = next(row for row in alerts if row['rule'] == 'PASSWORD_SPRAYING')
    # -- evidence preserved
    evidence = sqlite3.connect(str(pipeline)).execute(
        'SELECT evidence_json FROM alerts WHERE id = (SELECT MAX(id) FROM alerts)'
    ).fetchone()[0]
    assert '203.0.113.66' in evidence and 'affected_users' in evidence
    # -- event IDs preserved and reference stored events
    listed = sqlite3.connect(str(pipeline)).execute(
        'SELECT source_event_ids_json FROM alerts WHERE rule = "PASSWORD_SPRAYING" '
        'ORDER BY id DESC LIMIT 1').fetchone()[0]
    import json
    listed = json.loads(listed)
    assert set(listed) <= set(event_ids) and listed
    # -- correlation ID exists
    assert spray['correlation_id']
    # -- deterministic risk exists and is explainable; the fully-developed
    # spray (5 users, 10+ windowed events, known-malicious IP) scores higher.
    assert spray['deterministic_risk_score'] >= 55
    assert max(row['deterministic_risk_score'] for row in alerts
               if row['rule'] == 'PASSWORD_SPRAYING') >= 60
    factors = sqlite3.connect(str(pipeline)).execute(
        'SELECT risk_factors_json FROM alerts WHERE rule = "PASSWORD_SPRAYING" '
        'ORDER BY id DESC LIMIT 1').fetchone()[0]
    assert 'threat_intel' in factors
    # -- Jev metadata exists (mock)
    assert spray['jev_priority'] in ('low', 'medium', 'high', 'critical')
    assert spray['jev_status'] == 'ok'
    assert spray['rule_id'] == 'TW-004'
    assert 'T1110.003' in spray['mitre_techniques_json']
    # -- correlation table row exists
    with _db(pipeline) as connection:
        count = connection.execute(
            'SELECT COUNT(*) FROM correlations WHERE correlation_id = ?',
            (spray['correlation_id'],)).fetchone()[0]
    assert count == 1


def test_duplicate_alerts_suppressed_within_cooldown(pipeline):
    users = ['u1', 'u2', 'u3']
    for _ in range(3):
        for user in users:
            process_event({'type': 'auth_failed', 'src': '198.51.100.9', 'user': user})
    first_count = len(_soc_alerts(pipeline))
    assert first_count >= 1
    # Another spray burst from the SAME source within the cooldown window:
    for user in ('u1', 'u2', 'u3'):
        process_event({'type': 'auth_failed', 'src': '198.51.100.9', 'user': user})
    second_count = len(_soc_alerts(pipeline))
    assert second_count == first_count       # no duplicates


def test_jev_unavailable_detection_still_works(pipeline):
    """Jev disabled/unavailable: deterministic pipeline still produces alerts."""
    # Default fixture provider is the disabled one (JEV_ENABLED unset).
    for user in ('jane', 'joe', 'jack'):
        process_event({'type': 'auth_failed', 'src': '192.0.2.50', 'user': user})
    alerts = _soc_alerts(pipeline)
    assert alerts
    assert {row['rule'] for row in alerts} >= {'PASSWORD_SPRAYING'}
    for row in alerts:
        assert row['deterministic_risk_score'] is not None
        assert row['jev_status'] == 'fallback'
        assert row['jev_priority'] == 'medium'      # safe fallback decision
        assert row['investigation_status'] == 'new'


def test_jev_disabled_via_config_keeps_pipeline_intact(pipeline, monkeypatch):
    detector.reload_soc_components({'JEV_ENABLED': 'false'})   # explicit
    monkeypatch.setattr(detector, '_provider',
                        detector.make_provider({'enabled': False, 'model': 'm',
                                                'timeout_seconds': 5,
                                                'api_key': '', 'endpoint': ''}))
    process_event({'type': 'port_scan', 'src': '198.51.100.77', 'ports': [1, 2, 3]})
    alerts = _soc_alerts(pipeline)
    assert any(row['rule'] == 'PORT_SCAN' for row in alerts)
    assert all(row['jev_status'] == 'fallback' for row in alerts)


def test_e2e_via_simulator_spray_scenario(tmp_path, monkeypatch):
    """Collector + spray scenario + detector, like a real deployment."""
    from collector import SimHandler, TailReader
    from database import init_db
    from simulator.catalog import SPRAY_EVENTS
    from simulator.append_events import write_jsonl

    dbfile = tmp_path / 'collector-spray.sqlite'
    logfile = tmp_path / 'spray.jsonl'
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    detector.DB = str(dbfile)
    detector.bad_ips = {}
    detector.reload_soc_components({})
    init_db(str(dbfile))
    write_jsonl(str(logfile), events=SPRAY_EVENTS)

    tail = TailReader(str(logfile), str(dbfile))
    SimHandler(str(logfile), tail=tail, db_file=str(dbfile)).drain()
    with sqlite3.connect(str(dbfile)) as connection:
        events = connection.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        rows = connection.execute(
            'SELECT rule, deterministic_risk_score, correlation_id FROM alerts'
        ).fetchall()
    assert events == len(SPRAY_EVENTS)
    rules = {row[0] for row in rows}
    assert 'PASSWORD_SPRAYING' in rules
    assert all(row[1] is not None and row[2] for row in rows)
