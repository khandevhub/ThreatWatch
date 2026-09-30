"""Detector tests.

The original test set DB_FILE after the detector module had already been
imported (module-level constant), so the temp path never took effect. These
tests set the environment first and import the module afterwards.
"""
import os
import sqlite3

import pytest


@pytest.fixture()
def detector(tmp_path, monkeypatch):
    dbfile = tmp_path / 'test_db.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    monkeypatch.setenv('THREAT_INTEL', str(tmp_path / 'intel.csv'))  # empty by default
    import detector
    # detector reads DB_FILE/THREAT_INTEL into module constants at import;
    # bind them explicitly so each test gets its own db and empty intel set.
    detector.DB = str(dbfile)
    detector.bad_ips = {}
    detector.failed_logins.clear()  # isolate sliding-window state between tests
    detector.init_db()
    yield detector
    detector.failed_logins.clear()


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
