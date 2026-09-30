"""Existing detector behavior and persisted-state regression tests."""
import importlib
import os
import sqlite3

import pytest


@pytest.fixture()
def detector(tmp_path, monkeypatch):
    dbfile = tmp_path / 'test_db.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))
    import detector
    detector.DB = str(dbfile)
    detector.bad_ips = {}
    detector.init_db(str(dbfile))
    yield detector

def _alert_count(dbfile):
    conn = sqlite3.connect(str(dbfile))
    try:
        return conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    finally:
        conn.close()


def test_no_alert_below_bruteforce_threshold(detector, tmp_path):
    for _ in range(4):
        detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})
    assert _alert_count(tmp_path / 'test_db.sqlite') == 0


def test_bruteforce_alert_at_threshold(detector, tmp_path):
    for _ in range(5):
        detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})
    dbfile = tmp_path / 'test_db.sqlite'
    conn = sqlite3.connect(str(dbfile))
    try:
        row = conn.execute(
            'SELECT rule, severity FROM alerts ORDER BY id DESC LIMIT 1').fetchone()
    finally:
        conn.close()
    assert row is not None and row[0] == 'BRUTE_FORCE' and row[1] == 'HIGH'


def test_bruteforce_counter_resets_after_alert(detector, tmp_path):
    for _ in range(5):
        detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})
    for _ in range(4):
        detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})
    assert _alert_count(tmp_path / 'test_db.sqlite') == 1  # only the first alert


def test_bruteforce_sources_are_tracked_independently(detector, tmp_path):
    for _ in range(4):
        detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})
    for _ in range(5):
        detector.process_event({'type': 'auth_failed', 'src': '5.6.7.8'})
    assert _alert_count(tmp_path / 'test_db.sqlite') == 1


def test_port_scan_alert(detector, tmp_path):
    detector.process_event({'type': 'port_scan', 'src': '9.9.9.9', 'ports': [22, 80]})
    conn = sqlite3.connect(str(tmp_path / 'test_db.sqlite'))
    try:
        row = conn.execute(
            'SELECT rule, severity FROM alerts ORDER BY id DESC LIMIT 1').fetchone()
    finally:
        conn.close()
    assert row == ('PORT_SCAN', 'MEDIUM')


def test_traffic_spike_alert(detector, tmp_path):
    detector.process_event({'type': 'traffic_spike', 'bytes': 12345678})
    conn = sqlite3.connect(str(tmp_path / 'test_db.sqlite'))
    try:
        row = conn.execute(
            'SELECT rule, severity FROM alerts ORDER BY id DESC LIMIT 1').fetchone()
    finally:
        conn.close()
    assert row == ('TRAFFIC_SPIKE', 'LOW')


def test_unknown_event_type_is_ignored(detector, tmp_path):
    detector.process_event({'type': 'something_else'})
    assert _alert_count(tmp_path / 'test_db.sqlite') == 0


def test_bruteforce_uses_event_time_window(detector, tmp_path):
    attempts = [
        '2025-01-01T00:00:00Z',
        '2025-01-01T00:00:01Z',
        '2025-01-01T00:00:02Z',
        '2025-01-01T00:00:03Z',
    ]
    for event_time in attempts:
        detector.process_event({
            'type': 'auth_failed', 'src': '1.2.3.4', 'event_time': event_time,
        })
    detector.process_event({
        'type': 'auth_failed', 'src': '1.2.3.4',
        'event_time': '2025-01-01T00:01:01Z',
    })
    assert _alert_count(tmp_path / 'test_db.sqlite') == 0


def test_bruteforce_window_survives_detector_restart(detector, tmp_path):
    for _ in range(4):
        detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})

    restarted_detector = importlib.reload(detector)
    restarted_detector.DB = str(tmp_path / 'test_db.sqlite')
    restarted_detector.bad_ips = {}
    restarted_detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})

    assert _alert_count(tmp_path / 'test_db.sqlite') == 1


def test_replayed_event_id_does_not_increment_bruteforce_count(detector, tmp_path):
    for _ in range(4):
        detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})
    repeated = {'event_id': 'stable-event-id', 'type': 'auth_failed', 'src': '1.2.3.4'}
    assert detector.process_event(repeated) is True
    assert detector.process_event(repeated) is False
    assert _alert_count(tmp_path / 'test_db.sqlite') == 1
