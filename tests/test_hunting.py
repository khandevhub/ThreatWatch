"""Phase 3D: hunting query layer — filters, limits, injection, linkage."""
import sqlite3

import pytest

import detector
from detector import process_event
from hunting import (DEFAULT_LIMIT, HuntError, MAX_LIMIT, hunt,
                     parse_hunt_filters)


def _db(tmp_path):
    return str(tmp_path / 'hunt.sqlite')


@pytest.fixture()
def event_db(tmp_path, monkeypatch):
    """Database with a handful of directly inserted, well-known events."""
    dbfile = _db(tmp_path)
    monkeypatch.setenv('DB_FILE', dbfile)
    detector.DB = dbfile
    detector.reload_soc_components({})
    detector.init_db(dbfile)
    rows = [
        # event_id, event_time, host, user, src_ip, event_type, command, url, hash
        ('h1', '2025-01-01T00:00:01Z', 'ws1', 'alice', '10.0.0.1', 'auth_failed',
         None, None, None),
        ('h2', '2025-01-01T00:00:02Z', 'ws1', 'bob', '10.0.0.2', 'process_start',
         'powershell -nop alpha_one', None, None),
        ('h3', '2025-01-01T00:00:03Z', 'ws2', 'carol', '10.0.0.1', 'process_start',
         'echo 100%_done && curl -H "Authorization: Bearer leak123" http://x',
         'http://bad.example/x?a=1', 'a' * 64),
        ('h4', '2025-01-02T00:00:00Z', 'ws2', 'alice', '10.0.0.3', 'process_start',
         'run alphaXone now', None, None),
    ]
    with sqlite3.connect(dbfile) as connection:
        connection.executemany(
            '''INSERT INTO events (event_id, schema_version, event_time,
               ingestion_time, source, source_type, host, user_name, src_ip,
               event_type, command_line, url, file_hash, metadata_json)
               VALUES (?, 1, ?, '2025-01-01T00:00:00Z', 'test', 'synthetic',
                       ?, ?, ?, ?, ?, ?, ?, '{}')''',
            rows)
        connection.commit()
    return dbfile


# -- filter parsing ---------------------------------------------------------

def test_unknown_filter_fails_closed():
    with pytest.raises(HuntError):
        parse_hunt_filters({'not_a_filter': 'x'})


def test_filters_must_be_a_mapping():
    with pytest.raises(HuntError):
        parse_hunt_filters([('src_ip', '10.0.0.1')])
    with pytest.raises(HuntError):
        parse_hunt_filters('src_ip=10.0.0.1')


def test_exact_filters_are_validated():
    assert parse_hunt_filters({'src_ip': '10.0.0.1'})[1] == ['10.0.0.1']
    for bad in ('999.1.1.1', '1.2.3.4 OR 1=1', '10.0.0.1; --'):
        with pytest.raises(HuntError):
            parse_hunt_filters({'src_ip': bad})
    assert parse_hunt_filters({'file_hash': 'A' * 64})[1] == ['A' * 64]
    with pytest.raises(HuntError):
        parse_hunt_filters({'file_hash': 'zz-not-a-hash'})


def test_substring_filters_reject_unsafe_characters():
    assert parse_hunt_filters({'user': 'alice'})[1] == ['%alice%']
    for payload in ("'; DROP TABLE events; --", 'alice<script>', 'a(b)', '%*!'):
        with pytest.raises(HuntError):
            parse_hunt_filters({'user': payload})


def test_like_wildcards_are_escaped_not_interpreted():
    # Underscores reach the LIKE layer and must be escaped, not wildcarded.
    clauses, params, _ = parse_hunt_filters({'command': 'a_one'})
    assert params == ['%a\\_one%']
    assert "ESCAPE '\\'" in clauses[0]
    # URL-encoded input is decoded first, then escaped the same way.
    assert parse_hunt_filters({'command': 'a%5Fone'})[1] == ['%a\\_one%']
    # A literal '%' can never reach the LIKE layer: the character allowlist
    # rejects it fail-closed (so it can never broaden the query).
    with pytest.raises(HuntError):
        parse_hunt_filters({'command': '100%'})


def test_time_filters_are_iso_validated():
    clauses, params, _ = parse_hunt_filters(
        {'time_from': '2025-01-01', 'time_to': '2025-01-02T10:00:00Z'})
    assert clauses == ['event_time >= ?', 'event_time <= ?']
    assert params == ['2025-01-01', '2025-01-02T10:00:00Z']
    for bad in ('yesterday', '2025-13-40', '2025-01-01; DROP'):
        with pytest.raises(HuntError):
            parse_hunt_filters({'time_from': bad})


def test_technique_filter_shape_is_enforced():
    _, _, link = parse_hunt_filters({'technique': 't1059.001'})
    assert link == {'technique': 'T1059.001'}
    for bad in ('T1110; --', 'password spraying', 'T11', 'TX1110'):
        with pytest.raises(HuntError):
            parse_hunt_filters({'technique': bad})


def test_empty_and_blank_filters_are_ignored():
    clauses, params, link = parse_hunt_filters({'src_ip': '', 'user': None,
                                                'event_type': 'auth_failed'})
    assert clauses == ['event_type = ?'] and params == ['auth_failed']
    assert link == {}


# -- hunt behaviour ----------------------------------------------------------

def test_hunt_without_filters_returns_all_events_bounded(event_db):
    result = hunt({}, db_file=event_db)
    assert result['total'] == 4
    assert result['limit'] == DEFAULT_LIMIT
    assert len(result['results']) == 4


def test_hunt_exact_and_substring_filters(event_db):
    assert [row['event_id'] for row in
            hunt({'src_ip': '10.0.0.1'}, db_file=event_db)['results']] == ['h1', 'h3']
    assert [row['event_id'] for row in
            hunt({'user': 'alice'}, db_file=event_db)['results']] == ['h1', 'h4']
    assert [row['event_id'] for row in
            hunt({'event_type': 'process_start'}, db_file=event_db)['results']] == \
        ['h2', 'h3', 'h4']
    assert [row['event_id'] for row in
            hunt({'file_hash': 'a' * 64}, db_file=event_db)['results']] == ['h3']


def test_hunt_combined_filters_are_anded(event_db):
    result = hunt({'src_ip': '10.0.0.1', 'user': 'alice'}, db_file=event_db)
    assert [row['event_id'] for row in result['results']] == ['h1']


def test_hunt_like_wildcards_match_literally(event_db):
    # '_' matches the literal underscore in 'alpha_one' (h2), never the
    # 'alphaXone' variant (h4) — an unescaped '_' would match both.
    hits = hunt({'command': 'a_one'}, db_file=event_db)['results']
    assert [row['event_id'] for row in hits] == ['h2']


def test_hunt_time_window(event_db):
    result = hunt({'time_from': '2025-01-02'}, db_file=event_db)
    assert [row['event_id'] for row in result['results']] == ['h4']
    result = hunt({'time_to': '2025-01-01T00:00:02Z'}, db_file=event_db)
    assert [row['event_id'] for row in result['results']] == ['h1', 'h2']


def test_hunt_is_deterministic(event_db):
    first = hunt({'src_ip': '10.0.0.1'}, db_file=event_db)
    second = hunt({'src_ip': '10.0.0.1'}, db_file=event_db)
    assert first == second


def test_hunt_pagination_is_safe(event_db):
    page = hunt({}, db_file=event_db, limit=2, offset=1)
    assert page['total'] == 4 and len(page['results']) == 2
    assert [row['event_id'] for row in page['results']] == ['h2', 'h3']
    last = hunt({}, db_file=event_db, limit=2, offset=2)
    assert [row['event_id'] for row in last['results']] == ['h3', 'h4']
    empty = hunt({}, db_file=event_db, limit=10, offset=100)
    assert empty['results'] == [] and empty['total'] == 4


def test_hunt_limit_bounds(event_db):
    assert hunt({}, db_file=event_db, limit=MAX_LIMIT)['limit'] == MAX_LIMIT
    for bad_limit in (0, -1, MAX_LIMIT + 1, 'many'):
        with pytest.raises(HuntError):
            hunt({}, db_file=event_db, limit=bad_limit)
    with pytest.raises(HuntError):
        hunt({}, db_file=event_db, offset=-1)
    with pytest.raises(HuntError):
        hunt({}, db_file=event_db, offset='x')


def test_hunt_results_are_secret_safe(event_db):
    result = hunt({'command': 'curl'}, db_file=event_db)
    serialized = str(result)
    assert 'leak123' not in serialized
    assert '***REDACTED***' in serialized


def test_hunt_sql_injection_attempts_do_not_execute(event_db):
    rejected = [
        {'src_ip': "10.0.0.1' OR '1'='1"},
        {'user': "alice'; DROP TABLE events; --"},
        {'command': "x' UNION SELECT 1,2,3 --"},
        {'not_a_filter': "1=1); DROP TABLE events; --"},
        {'time_from': "2025-01-01' OR '1'='1"},
    ]
    for payload in rejected:
        with pytest.raises(HuntError):
            hunt(payload, db_file=event_db)
    # Exact-match values are always bound as parameters: injection strings can
    # never execute — they just match nothing.
    harmless = hunt({'event_type': "auth_failed' UNION SELECT 1,2,3 --"},
                    db_file=event_db)
    assert harmless['total'] == 0 and harmless['results'] == []
    # Nothing leaked or destroyed: the events table is intact and unchanged.
    assert hunt({}, db_file=event_db)['total'] == 4


def test_hunt_missing_filters_yield_empty_not_unfiltered(event_db):
    assert hunt({'src_ip': '203.0.113.99'}, db_file=event_db)['total'] == 0
    assert hunt({'event_type': 'no_such_type'}, db_file=event_db)['results'] == []


# -- alert linkage ------------------------------------------------------------

@pytest.fixture()
def linked_db(tmp_path, monkeypatch):
    dbfile = _db(tmp_path)
    monkeypatch.setenv('DB_FILE', dbfile)
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    detector.DB = dbfile
    detector.reload_soc_components({})
    detector.init_db(dbfile)
    for round_no in range(2):
        for user in ('alice', 'bob', 'carol'):
            process_event({'event_id': f'link-{round_no}-{user}',
                           'type': 'auth_failed', 'src': '203.0.113.5',
                           'user': user})
    return dbfile


def _one_alert(dbfile):
    with sqlite3.connect(dbfile) as connection:
        return connection.execute(
            'SELECT id, correlation_id, mitre_techniques_json FROM alerts '
            'ORDER BY id DESC LIMIT 1').fetchone()


def test_hunt_by_alert_id_returns_only_linked_events(linked_db):
    alert_id, correlation_id, _ = _one_alert(linked_db)
    result = hunt({'alert_id': str(alert_id)}, db_file=linked_db)
    assert result['total'] >= 3
    assert all(row['event_id'].startswith('link-') for row in result['results'])


def test_hunt_unknown_alert_id_yields_empty(linked_db):
    result = hunt({'alert_id': '999999'}, db_file=linked_db)
    assert result['total'] == 0 and result['results'] == []


def test_hunt_by_correlation_id(linked_db):
    _, correlation_id, _ = _one_alert(linked_db)
    result = hunt({'correlation_id': correlation_id}, db_file=linked_db)
    assert result['total'] >= 3
    unknown = hunt({'correlation_id': '00000000-0000-0000-0000-000000000000'},
                   db_file=linked_db)
    assert unknown['total'] == 0


def test_hunt_by_technique_is_quote_delimited(linked_db):
    _, _, stored = _one_alert(linked_db)
    assert 'T1110.003' in stored
    # A spray-only alert must surface for the sub-technique but NOT for the
    # bare parent id: matching is quote-delimited ("T1110" != "T1110.003").
    with sqlite3.connect(linked_db) as connection:
        connection.execute(
            "INSERT INTO events (event_id, schema_version, event_time, "
            "ingestion_time, source, source_type, event_type, metadata_json) "
            "VALUES ('spray-only-event', 1, '2025-01-01T00:00:00Z', "
            "'2025-01-01T00:00:00Z', 'test', 'synthetic', 'auth_failed', '{}')")
        connection.execute(
            "INSERT INTO alerts (time, rule, severity, details, rule_id, "
            "mitre_techniques_json, source_event_ids_json) "
            "VALUES ('2025-01-01T00:00:00Z', 'PASSWORD_SPRAYING', 'HIGH', "
            "'spray-only row', 'TW-004', '[\"T1110.003\"]', "
            "'[\"spray-only-event\"]')")
        connection.commit()
    sub = hunt({'technique': 'T1110.003'}, db_file=linked_db)
    assert 'spray-only-event' in {row['event_id'] for row in sub['results']}
    parent = hunt({'technique': 'T1110'}, db_file=linked_db)
    assert 'spray-only-event' not in {row['event_id'] for row in parent['results']}
    # A technique no alert stores returns nothing.
    assert hunt({'technique': 'T1046'}, db_file=linked_db)['total'] == 0


def test_hunt_link_and_content_filters_combine(linked_db):
    alert_id, _, _ = _one_alert(linked_db)
    result = hunt({'alert_id': str(alert_id), 'user': 'alice'},
                  db_file=linked_db)
    assert 0 < result['total'] <= 3
    assert all(row['user'] == 'alice' for row in result['results'])


def test_hunt_link_filters_reject_malformed_values(linked_db):
    for payload in ({'alert_id': '1; DROP TABLE alerts'},
                    {'alert_id': 'not-a-number'},
                    {'correlation_id': "x' OR '1'='1"},
                    {'technique': "T1110'"}):
        with pytest.raises(HuntError):
            hunt(payload, db_file=linked_db)
