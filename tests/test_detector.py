import os, sqlite3, tempfile
import pytest
from detector import init_db, process_event
def test_bruteforce_threshold(tmp_path, monkeypatch):
    dbfile = tmp_path / 'db.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    init_db()
    for _ in range(5):
        process_event({'type':'auth_failed', 'src':'1.2.3.4'})
    conn = sqlite3.connect(str(dbfile))
    c = conn.cursor()
    c.execute("SELECT rule, severity FROM alerts ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    assert row is not None and row[0] == 'BRUTE_FORCE'
    conn.close()

def test_intel_flagging(tmp_path, monkeypatch):
    dbfile = tmp_path / 'db2.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    intel = tmp_path / 'intel.csv'
    intel.write_text('ip,tag,source\n10.0.0.6,BAD,manual\n')
    monkeypatch.setenv('INTEL_FILE', str(intel))
    init_db()
    process_event({'type':'port_scan','src':'10.0.0.6','ports':[22,80]})
    conn = sqlite3.connect(str(dbfile))
    c = conn.cursor()
    c.execute("SELECT rule, severity, details FROM alerts ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    assert row is not None
    assert 'KNOWN_THREAT' in row[2] or row[1] in ('HIGH','CRITICAL')
    conn.close()
