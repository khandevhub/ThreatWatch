"""Correlation engine: grouping, evidence merge, IDs, and suppression."""
import sqlite3

from correlator import Correlator, new_correlation_id
from detections import DetectionFinding


def finding(rule_id, severity, source_ip=None, domain=None, hostname=None,
            users=(), event_ids=('e1',), confidence=0.7, name=None):
    evidence = {}
    if source_ip:
        evidence['source_ip'] = source_ip
    if domain:
        evidence['domain'] = domain
    if hostname:
        evidence['hostname'] = hostname
    if users:
        evidence['affected_users'] = list(users)
        evidence['affected_user_count'] = len(users)
    return DetectionFinding(
        detection_id=f'd-{rule_id}-{event_ids[0]}',
        rule_id=rule_id, rule_name=name or rule_id, severity=severity,
        confidence=confidence, description='test finding',
        event_ids=tuple(event_ids), evidence=evidence,
        tags=('tag',), mitre=('T0000',), primary_event_id=event_ids[0])


def test_single_finding_gets_correlation_id():
    groups = Correlator().group_findings([finding('TW-001', 'HIGH', source_ip='1.2.3.4')])
    assert len(groups) == 1
    assert groups[0].correlation_id
    assert groups[0].key == 'source_ip:1.2.3.4'


def test_findings_sharing_source_ip_merge():
    correlator = Correlator()
    a = finding('TW-001', 'HIGH', source_ip='1.2.3.4', users=('root',), event_ids=('e1',))
    b = finding('TW-004', 'HIGH', source_ip='1.2.3.4', users=('alice',), event_ids=('e2', 'e3'))
    groups = correlator.group_findings([a, b])
    assert len(groups) == 1
    group = groups[0]
    assert group.correlation_id
    assert set(group.event_ids) == {'e1', 'e2', 'e3'}
    assert group.evidence['event_count'] == 3
    assert set(group.evidence['affected_users']) == {'root', 'alice'}
    assert group.evidence['affected_user_count'] == 2
    assert set(group.evidence['rule_ids']) == {'TW-001', 'TW-004'}
    assert set(group.mitre) == {'T0000'}
    assert len(group.findings) == 2


def test_different_indicators_do_not_merge():
    correlator = Correlator()
    groups = correlator.group_findings([
        finding('TW-001', 'HIGH', source_ip='1.2.3.4'),
        finding('TW-001', 'HIGH', source_ip='5.6.7.8'),
        finding('TW-010', 'MEDIUM', domain='mail.corp.com'),
        finding('TW-005', 'HIGH', hostname='ws1'),
    ])
    assert len(groups) == 4          # four distinct indicators -> four groups
    assert {g.key for g in groups} == {
        'source_ip:1.2.3.4', 'source_ip:5.6.7.8',
        'domain:mail.corp.com', 'host:ws1'}


def test_severity_and_confidence_take_maximum():
    correlator = Correlator()
    groups = correlator.group_findings([
        finding('TW-001', 'HIGH', source_ip='1.2.3.4', confidence=0.9),
        finding('TW-006', 'LOW', source_ip='1.2.3.4', confidence=0.4),
    ])
    assert groups[0].severity == 'HIGH'
    assert groups[0].confidence == 0.9


def test_unknown_source_falls_back_to_host_then_event():
    correlator = Correlator()
    groups = correlator.group_findings([
        finding('TW-005', 'HIGH', hostname='ws1'),
        finding('TW-006', 'HIGH', hostname='ws1'),
    ])
    assert len(groups) == 1 and groups[0].key == 'host:ws1'
    solo = correlator.group_findings([
        finding('TW-005', 'LOW', hostname='unknown', event_ids=('solo',))])
    assert solo[0].key.startswith('event:')


def test_duplicate_suppression_within_cooldown():
    connection = sqlite3.connect(':memory:')
    connection.row_factory = sqlite3.Row
    correlator = Correlator(cooldown_seconds=300)
    correlator.init_suppression_table(connection)
    assert correlator.is_suppressed(connection, 'TW-001', '1.2.3.4') is False
    correlator.mark_alerted(connection, 'TW-001', '1.2.3.4')
    assert correlator.is_suppressed(connection, 'TW-001', '1.2.3.4') is True
    assert correlator.is_suppressed(connection, 'TW-001', '5.6.7.8') is False
    assert correlator.is_suppressed(connection, 'TW-004', '1.2.3.4') is False


def test_correlation_ids_are_unique():
    assert new_correlation_id() != new_correlation_id()
