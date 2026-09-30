"""Versioned normalized event contract tests."""
from datetime import datetime

import pytest

from event_model import EventValidationError, SecurityEvent


def test_legacy_simulator_event_normalizes_fields_and_time():
    event = SecurityEvent.from_payload({
        'type': 'auth_failed',
        'src': '2001:0db8::1',
        'time': '2025-01-02T03:04:05+02:00',
        'message': 'Failed password',
    }, default_source='jsonl', generated_event_id='line:1')

    assert event.event_id == 'line:1'
    assert event.schema_version == 1
    assert event.event_time == '2025-01-02T01:04:05.000000Z'
    assert datetime.fromisoformat(event.ingestion_time.replace('Z', '+00:00')).tzinfo is not None
    assert event.source == 'jsonl'
    assert event.source_type == 'authentication'
    assert event.event_type == 'auth_failed'
    assert event.action == 'login'
    assert event.outcome == 'failure'
    assert event.src_ip == '2001:db8::1'
    assert event.metadata == {'message': 'Failed password'}


def test_current_simulator_network_fields_are_preserved():
    port_scan = SecurityEvent.from_payload({
        'type': 'port_scan', 'src': '9.9.9.9', 'ports': [22, 443],
    })
    spike = SecurityEvent.from_payload({'type': 'traffic_spike', 'bytes': 1024})

    assert port_scan.source_type == 'network'
    assert port_scan.metadata['ports'] == [22, 443]
    assert spike.metadata['bytes'] == 1024
    assert spike.src_ip is None


@pytest.mark.parametrize('payload', [
    [],
    {'type': ''},
    {'type': 'auth_failed', 'schema_version': True},
    {'type': 'auth_failed', 'schema_version': 2},
    {'type': 'auth_failed', 'src': 'not-an-ip'},
    {'type': 'port_scan', 'ports': [0]},
    {'type': 'auth_failed', 'metadata': []},
    {'type': 'auth_failed', 'unexpected': 'value'},
    {'type': 'auth_failed', 'time': 'not-a-time'},
    {'type': 'auth_failed', 'event_time': '2025-01-01T00:00:00Z',
     'time': '2025-01-02T00:00:00Z'},
])
def test_malformed_events_are_rejected(payload):
    with pytest.raises(EventValidationError):
        SecurityEvent.from_payload(payload)


def test_future_event_families_fit_the_contract():
    families = ('authentication', 'process', 'network', 'dns', 'web',
                'powershell', 'endpoint', 'cloud_identity')
    for family in families:
        event = SecurityEvent.from_payload({
            'event_type': 'future_event',
            'source_type': family,
            'host': 'workstation-1',
            'user': 'analyst',
            'process': 'powershell.exe',
            'command_line': 'powershell -NoProfile',
            'domain': 'example.test',
            'url': 'https://example.test/path',
            'file_hash': 'a' * 64,
            'metadata': {'family': family},
        })
        assert event.source_type == family
        assert event.host == 'workstation-1'
        assert event.to_dict()['metadata'] == {'family': family}
