"""Phase 3B/3C/3E/3F: investigation package tests."""
import json
import sqlite3

import pytest

import detector
from investigation import (InvestigationError, InvestigationService,
                           MAX_QUESTIONS)
from rules import ATTACK_TECHNIQUE_NAMES
from detector import process_event


@pytest.fixture()
def investigated(tmp_path, monkeypatch):
    dbfile = tmp_path / 'investigation.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    intel = tmp_path / 'intel.csv'
    intel.write_text('ip,tag,confidence,source\n203.0.113.7,spray_source,0.9,test-feed\n',
                     encoding='utf-8')
    monkeypatch.setenv('THREAT_INTEL', str(intel))
    detector.DB = str(dbfile)
    detector.reload_soc_components({})
    detector.init_db(str(dbfile))
    users = ('alice', 'bob', 'carol')
    for round_no in range(2):
        for user in users:
            process_event({'event_id': f'inv-{round_no}-{user}',
                           'type': 'auth_failed', 'src': '203.0.113.7',
                           'user': user})
    process_event({'event_id': 'inv-ps', 'event_type': 'powershell_script',
                   'host': 'ws1', 'user': 'alice',
                   'command_line': 'powershell -nop -enc SQBFAFgAIA=='})
    with sqlite3.connect(str(dbfile)) as connection:
        alert_id = connection.execute(
            'SELECT id FROM alerts WHERE rule = "PASSWORD_SPRAYING" '
            'ORDER BY id DESC LIMIT 1').fetchone()[0]
    return InvestigationService(db_file=str(dbfile)), alert_id, dbfile


def test_package_contains_all_required_sections(investigated):
    service, alert_id, _ = investigated
    package = service.build_investigation(alert_id)
    for section in ('alert', 'risk', 'evidence', 'timeline', 'indicators',
                    'threat_intel', 'mitre', 'related_alerts',
                    'investigation_questions'):
        assert section in package, section
    assert package['alert']['alert_id'] == alert_id
    assert package['risk']['score'] is not None
    assert package['evidence']['rule_code'] == 'PASSWORD_SPRAYING'


def test_package_is_deterministic_and_json_serializable(investigated):
    service, alert_id, _ = investigated
    first = json.dumps(service.build_investigation(alert_id), sort_keys=True)
    second = json.dumps(service.build_investigation(alert_id), sort_keys=True)
    assert first == second
    json.loads(first)


def test_evidence_entities_and_event_count(investigated):
    service, alert_id, _ = investigated
    package = service.build_investigation(alert_id)
    evidence = package['evidence']
    assert evidence['entities']['usernames'] == ['alice', 'bob', 'carol']
    assert evidence['entities']['source_ips'] == ['203.0.113.7']
    assert evidence['event_count'] == len(evidence['event_ids'])
    # The merged spray alert covers every sprayed user; the exact event count
    # depends on the detector's window, so only floor it at the spray threshold.
    assert evidence['event_count'] >= 3
    # Every listed event id resolves to a stored event, so the timeline and the
    # evidence agree on how much telemetry backs this alert.
    assert package['timeline']['total_events'] == evidence['event_count']


def test_threat_intel_context_flags_known_malicious(investigated):
    service, alert_id, _ = investigated
    package = service.build_investigation(alert_id)
    indicators = {item['indicator']: item for item in package['indicators']['indicators']}
    assert indicators['203.0.113.7']['known_malicious'] is True
    matches = package['threat_intel']['matches']
    assert any(match.get('indicator') == '203.0.113.7'
               and match.get('confidence') == 0.9 for match in matches)
    assert any(match.get('source') == 'stored_alert_enrichment'
               for match in matches)


def test_threat_intel_absent_when_feed_has_no_matches(tmp_path, monkeypatch):
    dbfile = tmp_path / 'no-intel.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    (tmp_path / 'intel.csv').write_text('ip,tag\n', encoding='utf-8')
    detector.DB = str(dbfile)
    detector.reload_soc_components({})
    detector.init_db(str(dbfile))
    for user in ('u1', 'u2', 'u3'):
        process_event({'type': 'auth_failed', 'src': '192.0.2.9', 'user': user})
    with sqlite3.connect(str(dbfile)) as connection:
        alert_id = connection.execute('SELECT id FROM alerts LIMIT 1').fetchone()[0]
    service = InvestigationService(db_file=str(dbfile))
    package = service.build_investigation(alert_id)
    # The pipeline alert stores its alert-time enrichment rows, so the section
    # carries that context, but the empty feed contributed no matches.
    feed_matches = [match for match in package['threat_intel']['matches']
                    if match.get('source') != 'stored_alert_enrichment']
    assert feed_matches == []
    assert package['indicators']['indicators']
    assert all(item['known_malicious'] is False
               for item in package['indicators']['indicators'])
    # An alert with no stored enrichment and no feed hits reports the gap.
    with sqlite3.connect(str(dbfile)) as connection:
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details) "
            "VALUES ('2025-01-01T00:00:00Z', 'PORT_SCAN', 'MEDIUM', 'bare row')")
        connection.commit()
        bare_id = connection.execute(
            'SELECT id FROM alerts WHERE details = "bare row"').fetchone()[0]
    bare = service.build_investigation(bare_id)
    assert bare['threat_intel'] == {'matches': [],
                                    'unavailable': ['threat_intel_matches']}


def test_attaack_context_uses_only_real_mappings_with_names(investigated):
    service, alert_id, _ = investigated
    package = service.build_investigation(alert_id)
    techniques = package['mitre']['techniques']
    assert techniques, 'spray alert must expose its stored mapping'
    # The fixture alert is the merged spray+brute-force correlation group, so
    # it legitimately carries both the spraying sub-technique and its parent.
    by_id = {technique['technique_id']: technique for technique in techniques}
    assert set(by_id) == {'T1110.003', 'T1110'}
    assert by_id['T1110.003']['technique_name'] == 'Password Spraying'
    assert by_id['T1110']['technique_name'] == 'Brute Force'
    for technique in techniques:
        assert technique['technique_name'] == ATTACK_TECHNIQUE_NAMES[technique['technique_id']]
        assert technique['suggested_next_step']
    # Techniques are attributed to the member rule that maps to them.
    assert by_id['T1110.003']['rule_id'] == 'TW-004'
    assert by_id['T1110']['rule_id'] == 'TW-001'
    assert package['mitre']['unavailable'] == []


def test_attaack_context_marks_unavailable_without_mapping(investigated):
    service, alert_id, dbfile = investigated
    with sqlite3.connect(str(dbfile)) as connection:
        connection.execute(
            "UPDATE alerts SET mitre_techniques_json = NULL WHERE id = ?", (alert_id,))
        connection.commit()
    package = service.build_investigation(alert_id)
    assert package['mitre']['unavailable'] == ['mitre_mapping']
    assert package['mitre']['techniques'] == []


def test_related_alerts_include_same_rule_history(investigated):
    service, alert_id, _ = investigated
    package = service.build_investigation(alert_id)
    related = package['related_alerts']['alerts']
    assert related, 'a second spray alert exists in the fixture'
    assert all(item['alert_id'] != alert_id for item in related)
    # Every SOC alert receives a fresh correlation id, so the only realistic
    # relation here is shared rule history.
    assert any(item['relation'] == 'same_rule' for item in related)


def test_related_alerts_include_correlation_members(investigated):
    """Alerts that explicitly share a correlation_id are surfaced first."""
    service, alert_id, dbfile = investigated
    with sqlite3.connect(str(dbfile)) as connection:
        shared = 'corr-shared-0001'
        connection.execute(
            'UPDATE alerts SET correlation_id = ? WHERE id = ?', (shared, alert_id))
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details, correlation_id) "
            "VALUES ('2025-01-02T00:00:00Z', 'BRUTE_FORCE', 'HIGH', 'member row', ?)",
            (shared,))
        connection.commit()
    package = service.build_investigation(alert_id)
    related = package['related_alerts']['alerts']
    members = [item for item in related if item['relation'] == 'correlation']
    assert members and members[0]['correlation_id'] == shared
    assert members[0]['rule'] == 'BRUTE_FORCE'


def test_investigation_questions_are_deterministic_and_bounded(investigated):
    service, alert_id, _ = investigated
    first = service.build_investigation(alert_id)['investigation_questions']
    second = service.build_investigation(alert_id)['investigation_questions']
    assert first == second
    assert 0 < len(first) <= MAX_QUESTIONS
    assert any('203.0.113.7' in question for question in first)
    assert any('T1110.003' in question for question in first)


def test_unavailable_evidence_marked_for_legacy_alert(investigated):
    service, alert_id, dbfile = investigated
    with sqlite3.connect(str(dbfile)) as connection:
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details) "
            "VALUES ('2025-01-01T00:00:00Z', 'PORT_SCAN', 'MEDIUM', 'legacy row')")
        connection.commit()
        legacy_id = connection.execute(
            'SELECT id FROM alerts WHERE details = "legacy row"').fetchone()[0]
    package = service.build_investigation(legacy_id)
    evidence = package['evidence']
    assert 'rule_metadata' in evidence['unavailable']
    assert 'risk_score' in evidence['unavailable']
    assert 'correlation_id' in evidence['unavailable']
    assert 'source_event_ids' in evidence['unavailable']
    assert package['risk']['score'] is None


def test_malformed_evidence_json_degrades_gracefully(investigated):
    service, alert_id, dbfile = investigated
    with sqlite3.connect(str(dbfile)) as connection:
        connection.execute(
            "UPDATE alerts SET evidence_json = '{not-json' WHERE id = ?", (alert_id,))
        connection.commit()
    package = service.build_investigation(alert_id)
    assert package['evidence']['entities']['usernames'] == []   # degraded, not crash


def test_missing_alert_raises_investigation_error(investigated):
    service, _, _ = investigated
    with pytest.raises(InvestigationError):
        service.build_investigation(999999)


def test_packages_are_secret_safe(investigated):
    service, alert_id, dbfile = investigated
    process_event({'event_id': 'inv-secret', 'event_type': 'process_start',
                   'host': 'ws1', 'user': 'alice',
                   'command_line': 'curl -H "Authorization: Bearer leak123" http://x'})
    package = service.build_investigation(alert_id)
    serialized = json.dumps(package)
    assert 'leak123' not in serialized
