import os, sqlite3
from detector import init_db, process_event, DB
def test_bruteforce(tmp_path, monkeypatch):
    dbfile = tmp_path / 'test_db.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    init_db()
    for _ in range(5):
        process_event({'type':'auth_failed','src':'1.2.3.4'})
    conn = sqlite3.connect(str(dbfile)); c = conn.cursor()
    c.execute('SELECT rule, severity FROM alerts ORDER BY id DESC LIMIT 1'); row = c.fetchone()
    assert row is not None and row[0]=='BRUTE_FORCE' and row[1]=='HIGH'