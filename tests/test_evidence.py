"""Phase 3A: evidence model, redaction, and timeline tests."""
import json

from evidence import (MAX_TIMELINE_ENTRIES, Evidence, build_timeline,
                      redact_text)


# -- secret redaction ----------------------------------------------------------

def test_key_value_secrets_are_masked():
    masked = redact_text('login failed: password=hunter2 for user bob')
    assert 'hunter2' not in masked
    assert 'password=' in masked and '***REDACTED***' in masked
    assert 'user bob' in masked            # unrelated text preserved


def test_api_key_and_token_forms_are_masked():
    for payload in ('api_key=sk-1234567890abcdef',
                    'api-key: sk-1234567890abcdef',
                    'token=ghp_abcdef1234567890',
                    'auth_token: "verysecretvalue"'):
        masked = redact_text(payload)
        assert 'sk-1234567890abcdef' not in masked, payload
        assert 'ghp_abcdef1234567890' not in masked, payload
        assert 'verysecretvalue' not in masked, payload


def test_bearer_token_in_authorization_header_is_masked():
    masked = redact_text('curl -H "Authorization: Bearer supersecret123" http://x')
    assert 'supersecret123' not in masked
    assert 'http://x' in masked            # non-secret context survives


def test_private_key_blocks_are_masked():
    block = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ\n-----END RSA PRIVATE KEY-----'
    masked = redact_text(f'uploaded {block} successfully')
    assert 'MIIEpAIBAAKCAQ' not in masked
    assert '***PRIVATE_KEY_REDACTED***' in masked


def test_redaction_is_idempotent_and_bounded():
    once = redact_text('password=secret123 and more text')
    assert redact_text(once) == once
    long_text = 'x' * 5000
    bounded = redact_text(long_text)
    assert len(bounded) == 512 and bounded.endswith('...')
    assert redact_text(None) is None


# -- timeline ------------------------------------------------------------------

def _rows(*specs):
    rows = []
    for spec in specs:
        row = {'event_id': spec[0], 'event_time': spec[1], 'event_type': spec[2]}
        rows.append(row)
    return rows


def test_timeline_orders_chronologically():
    timeline = build_timeline(_rows(
        ('e3', '2025-01-01T00:00:05Z', 'b'),
        ('e1', '2025-01-01T00:00:01Z', 'a'),
        ('e2', '2025-01-01T00:00:03Z', 'ab'),
    ), correlation_id='corr-1', related_alert='BRUTE_FORCE')
    ids = [entry['event_id'] for entry in timeline['entries']]
    assert ids == ['e1', 'e2', 'e3']
    assert all(entry['correlation_id'] == 'corr-1' for entry in timeline['entries'])
    assert timeline['entries'][0]['related_alert'] == 'BRUTE_FORCE'
    assert timeline['total_events'] == 3 and timeline['truncated'] is False


def test_identical_timestamps_tie_break_on_event_id():
    timeline = build_timeline(_rows(
        ('zz', '2025-01-01T00:00:00Z', 'a'),
        ('aa', '2025-01-01T00:00:00Z', 'a'),
        ('mm', '2025-01-01T00:00:00Z', 'a'),
    ))
    assert [entry['event_id'] for entry in timeline['entries']] == ['aa', 'mm', 'zz']


def test_missing_timestamps_sort_last_and_are_flagged():
    timeline = build_timeline(_rows(
        ('broken', '', 'a'),
        ('timed', '2025-01-01T00:00:00Z', 'a'),
    ))
    assert [entry['event_id'] for entry in timeline['entries']] == ['timed', 'broken']
    assert timeline['entries'][1]['timestamp_available'] is False
    assert timeline['entries'][1]['timestamp'] is None


def test_malformed_rows_are_kept_and_flagged_not_dropped():
    timeline = build_timeline([
        {'event_id': 'e1', 'event_time': None, 'event_type': None, 'source': 'x'},
        {'event_id': 'e2', 'event_time': 17, 'event_type': 42},   # wrong types
    ])
    assert timeline['total_events'] == 2
    flagged = [entry for entry in timeline['entries'] if not entry['timestamp_available']]
    assert len(flagged) == 2
    assert json.dumps(timeline)


def test_timeline_is_bounded():
    rows = _rows(*((f'e{n}', f'2025-01-01T00:{n // 60:02d}:{n % 60:02d}Z', 'a')
                   for n in range(MAX_TIMELINE_ENTRIES + 25)))
    timeline = build_timeline(rows)
    assert len(timeline['entries']) == MAX_TIMELINE_ENTRIES
    assert timeline['truncated'] is True
    assert timeline['total_events'] == MAX_TIMELINE_ENTRIES + 25


def test_timeline_entries_carry_requested_context():
    timeline = build_timeline(_rows(('e1', '2025-01-01T00:00:00Z', 'a')),
                              correlation_id='corr-9', related_alert='PORT_SCAN')
    entry = timeline['entries'][0]
    assert entry['correlation_id'] == 'corr-9'
    assert entry['related_alert'] == 'PORT_SCAN'


# -- evidence construction -----------------------------------------------------

def test_evidence_to_dict_is_json_serializable_and_deterministic():
    evidence = Evidence(
        alert_id=1, detection_id='d-1', rule_id='TW-004', rule_name='Password Spraying',
        rule_code='PASSWORD_SPRAYING', severity='HIGH',
        risk_factors={'confidence': 4, 'severity': 30},
        correlation_id='corr-1', source_ips=['2.2.2.2', '1.1.1.1'],
        usernames=['bob', 'alice'], event_ids=['e2', 'e1'], event_count=2,
    )
    as_dict = evidence.to_dict()
    serialized = json.dumps(as_dict, sort_keys=True)
    assert json.dumps(json.loads(serialized), sort_keys=True) == serialized
    assert as_dict['risk_factors'] == {'confidence': 4, 'severity': 30}
    assert as_dict['entities']['usernames'] == ['bob', 'alice']
    assert as_dict['entities']['source_ips'] == ['2.2.2.2', '1.1.1.1']
    again = Evidence(
        alert_id=1, detection_id='d-1', rule_id='TW-004', rule_name='Password Spraying',
        rule_code='PASSWORD_SPRAYING', severity='HIGH',
        risk_factors={'confidence': 4, 'severity': 30},
        correlation_id='corr-1', source_ips=['2.2.2.2', '1.1.1.1'],
        usernames=['bob', 'alice'], event_ids=['e2', 'e1'], event_count=2,
    )
    assert json.dumps(again.to_dict(), sort_keys=True) == serialized


def test_evidence_risk_factors_are_sorted_in_output():
    evidence = Evidence(risk_factors={'zebra': 1, 'alpha': 2, 'middle': 3})
    assert list(evidence.to_dict()['risk_factors']) == ['alpha', 'middle', 'zebra']


def test_unavailable_markers_deduplicate():
    evidence = Evidence()
    evidence.mark_unavailable('correlation_id')
    evidence.mark_unavailable('correlation_id')
    evidence.mark_unavailable('risk_score')
    assert evidence.to_dict()['unavailable'] == ['correlation_id', 'risk_score']


def test_evidence_description_is_redacted_in_output():
    evidence = Evidence(description='user ran curl -H "Authorization: Bearer leak123"')
    assert 'leak123' not in evidence.to_dict()['description']
