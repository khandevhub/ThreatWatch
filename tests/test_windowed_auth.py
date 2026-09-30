"""Windowed authentication detections: brute force and password spraying."""
import sqlite3

import pytest

import detector
from detector import process_event
from rules import load_rules


@pytest.fixture()
def detector_env(tmp_path, monkeypatch):
    dbfile = tmp_path / 'auth.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    detector.DB = str(dbfile)
    detector.bad_ips = {}
    detector.init_db(str(dbfile))
    yield detector


def _alert_rows(dbfile):
    with sqlite3.connect(str(dbfile)) as connection:
        return connection.execute(
            'SELECT rule, severity, deterministic_risk_score, correlation_id '
            'FROM alerts ORDER BY id').fetchall()


def test_single_account_hammer_is_brute_force_only(detector_env, tmp_path):
    for _ in range(5):
        process_event({'type': 'auth_failed', 'src': '1.2.3.4', 'user': 'root'})
    rows = _alert_rows(tmp_path / 'auth.sqlite')
    rules = {row[0] for row in rows}
    assert rules == {'BRUTE_FORCE'}            # no spray alert for one account


def test_multi_account_spray_fires_spray_and_brute(detector_env, tmp_path):
    users = ('alice', 'bob', 'carol')
    for user in users:
        process_event({'type': 'auth_failed', 'src': '9.9.9.9', 'user': user})
    for user in users:
        process_event({'type': 'auth_failed', 'src': '9.9.9.9', 'user': user})
    rows = _alert_rows(tmp_path / 'auth.sqlite')
    rules = [row[0] for row in rows]
    assert 'PASSWORD_SPRAYING' in rules        # 3 distinct users >= default 3
    # Brute force fires at the 5th failure; its finding merges into the same
    # source-IP correlation group as the spray finding (one merged alert).
    spray_row = next(row for row in rows if row[0] == 'PASSWORD_SPRAYING')
    assert spray_row[2] is not None and spray_row[3]
    with sqlite3.connect(str(tmp_path / 'auth.sqlite')) as connection:
        merged = connection.execute(
            "SELECT evidence_json FROM alerts WHERE rule = 'PASSWORD_SPRAYING'").fetchone()[0]
    assert 'TW-001' in merged                  # brute-force finding merged in


def test_spray_requires_distinct_users_not_repeats(detector_env, tmp_path):
    # 9 failures against ONE user from one source within the spray window:
    # brute force fires at 5; spraying (3 distinct users) never fires.
    for _ in range(9):
        process_event({'type': 'auth_failed', 'src': '8.8.4.4', 'user': 'svc'})
    rules = {row[0] for row in _alert_rows(tmp_path / 'auth.sqlite')}
    assert rules == {'BRUTE_FORCE'}


def test_spray_threshold_is_configurable(detector_env, tmp_path, monkeypatch):
    monkeypatch.setenv('SPRAY_MIN_USERS', '2')
    detector_env.reload_soc_components()
    for user in ('alice', 'bob'):
        process_event({'type': 'auth_failed', 'src': '7.7.7.7', 'user': user})
    rules = {row[0] for row in _alert_rows(tmp_path / 'auth.sqlite')}
    assert 'PASSWORD_SPRAYING' in rules


def test_brute_force_counter_resets_after_alert(detector_env, tmp_path):
    for _ in range(5):
        process_event({'type': 'auth_failed', 'src': '1.2.3.4', 'user': 'root'})
    for _ in range(4):
        process_event({'type': 'auth_failed', 'src': '1.2.3.4', 'user': 'root'})
    assert len(_alert_rows(tmp_path / 'auth.sqlite')) == 1


def test_window_expiry_prevents_old_failures_counting(detector_env, tmp_path):
    old = '2025-01-01T00:00:00Z'
    for _ in range(4):
        process_event({'type': 'auth_failed', 'src': '1.2.3.4', 'user': 'root',
                       'event_time': old})
    process_event({'type': 'auth_failed', 'src': '1.2.3.4', 'user': 'root',
                   'event_time': '2025-01-01T01:00:00Z'})
    assert _alert_rows(tmp_path / 'auth.sqlite') == []


def test_sources_are_tracked_independently(detector_env, tmp_path):
    for _ in range(4):
        process_event({'type': 'auth_failed', 'src': '1.2.3.4', 'user': 'root'})
    for _ in range(5):
        process_event({'type': 'auth_failed', 'src': '5.6.7.8', 'user': 'root'})
    assert len(_alert_rows(tmp_path / 'auth.sqlite')) == 1


def test_disabled_spray_rule_leaves_brute_force(detector_env, tmp_path, monkeypatch):
    monkeypatch.setenv('RULE_TW_004_ENABLED', 'false')
    detector_env.reload_soc_components({'RULE_TW_004_ENABLED': 'false'})
    for user in ('alice', 'bob', 'carol'):
        process_event({'type': 'auth_failed', 'src': '6.6.6.6', 'user': user})
    rules = {row[0] for row in _alert_rows(tmp_path / 'auth.sqlite')}
    assert 'PASSWORD_SPRAYING' not in rules
