"""Collector path-matching tests (Windows separator normalization).

Regression: watchdog delivers event paths with OS separators while the
watched path may use forward slashes; the collector missed every change
on Windows until _path_matches() normalized both sides.
"""
import os

from collector import SimHandler, TailReader, _path_matches


def test_matches_absolute_paths_with_mixed_separators():
    assert _path_matches(
        r'C:\some\dir\simulated_logs.jsonl', 'C:/some/dir/simulated_logs.jsonl')
    assert _path_matches(
        'C:/some/dir/simulated_logs.jsonl', r'C:\some\dir\simulated_logs.jsonl')


def test_matches_relative_paths_with_mixed_separators():
    assert _path_matches(r'.\simulated_logs.jsonl', './simulated_logs.jsonl')
    assert _path_matches('./simulated_logs.jsonl', r'.\simulated_logs.jsonl')


def test_does_not_match_other_files():
    assert not _path_matches(r'C:\other\log.jsonl', r'C:\some\dir\log.jsonl')
    assert not _path_matches('simulated_logs.jsonl2', 'simulated_logs.jsonl')


def test_sim_handler_processes_appends_end_to_end(tmp_path, monkeypatch):
    """The full on_modified flow: append lines -> drain() -> detector sees them."""
    dbfile = tmp_path / 'db.sqlite'
    logfile = tmp_path / 'simulated_logs.jsonl'
    logfile.write_text('', encoding='utf-8')

    monkeypatch.setenv('DB_FILE', str(dbfile))
    import detector
    detector.DB = str(dbfile)
    detector.bad_ips = {}
    detector.failed_logins.clear()
    detector.init_db()

    # simulate watchdog delivering a Windows-separator absolute path even
    # though the watched path was constructed with forward slashes
    watched_mixed = str(logfile).replace('\\', '/')
    handler = SimHandler(watched_mixed, tail=TailReader(watched_mixed))
    windows_style_event = type('E', (), {})()
    windows_style_event.src_path = str(logfile)          # backslashes
    windows_style_event.is_directory = False

    with open(logfile, 'a', encoding='utf-8') as fh:
        for _ in range(5):
            fh.write('{"type": "auth_failed", "src": "4.4.4.4"}\n')
    handler.on_modified(windows_style_event)

    import sqlite3
    conn = sqlite3.connect(str(dbfile))
    try:
        row = conn.execute('SELECT rule, severity FROM alerts ORDER BY id DESC LIMIT 1').fetchone()
    finally:
        conn.close()
    assert row == ('BRUTE_FORCE', 'HIGH')
