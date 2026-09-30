"""Durable JSONL tail-reader tests."""
import os

from collector import SimHandler, TailReader


def _tail(tmp_path, path):
    dbfile = tmp_path / 'state.sqlite'
    return TailReader(str(path), str(dbfile)), dbfile


def _lines(records):
    return [record.raw.decode('utf-8') for record in records]


def _ack(tail, records):
    for record in records:
        tail.acknowledge(record)


def test_reads_only_newly_appended_lines(tmp_path):
    logfile = tmp_path / 'log.jsonl'
    logfile.write_text('{"a": 1}\n', encoding='utf-8')
    tail, _ = _tail(tmp_path, logfile)
    initial = tail.read_new_lines()
    assert _lines(initial) == ['{"a": 1}']
    _ack(tail, initial)

    with open(logfile, 'a', encoding='utf-8') as stream:
        stream.write('{"a": 2}\n{"a": 3}\n')
    appended = tail.read_new_lines()
    assert _lines(appended) == ['{"a": 2}', '{"a": 3}']
    _ack(tail, appended)
    assert tail.read_new_lines() == []


def test_large_preexisting_file_is_processed_from_start(tmp_path):
    logfile = tmp_path / 'large.jsonl'
    logfile.write_text('{"old": 1}\n' * 50000, encoding='utf-8')
    tail, _ = _tail(tmp_path, logfile)
    first_batch = tail.read_new_lines(max_lines=10)
    assert len(first_batch) == 10
    assert first_batch[0].start_offset == 0
    _ack(tail, first_batch)
    next_batch = tail.read_new_lines(max_lines=10)
    assert len(next_batch) == 10
    assert next_batch[0].start_offset == first_batch[-1].end_offset


def test_truncation_starts_a_new_generation(tmp_path):
    logfile = tmp_path / 'log.jsonl'
    logfile.write_text('{"a": 1}\n', encoding='utf-8')
    tail, _ = _tail(tmp_path, logfile)
    first = tail.read_new_lines()
    _ack(tail, first)

    logfile.write_text('{"b": 9}\n', encoding='utf-8')
    rewritten = tail.read_new_lines()
    assert _lines(rewritten) == ['{"b": 9}']
    assert rewritten[0].generation == first[0].generation + 1


def test_same_size_rewrite_is_detected(tmp_path):
    logfile = tmp_path / 'log.jsonl'
    logfile.write_text('{"a": 1}\n', encoding='utf-8')
    tail, _ = _tail(tmp_path, logfile)
    first = tail.read_new_lines()
    _ack(tail, first)

    logfile.write_text('{"z": 9}\n', encoding='utf-8')
    rewritten = tail.read_new_lines()
    assert _lines(rewritten) == ['{"z": 9}']
    assert rewritten[0].generation == first[0].generation + 1


def test_partial_line_is_held_until_complete(tmp_path):
    logfile = tmp_path / 'log.jsonl'
    logfile.write_text('{"partial": ', encoding='utf-8')
    tail, _ = _tail(tmp_path, logfile)
    assert tail.read_new_lines() == []

    with open(logfile, 'a', encoding='utf-8') as stream:
        stream.write('1}\n')
    completed = tail.read_new_lines()
    assert _lines(completed) == ['{"partial": 1}']


def test_restart_resumes_after_the_last_acknowledged_byte(tmp_path):
    logfile = tmp_path / 'log.jsonl'
    logfile.write_text('{"a": 1}\n{"a": 2}\n', encoding='utf-8')
    tail, dbfile = _tail(tmp_path, logfile)
    initial = tail.read_new_lines()
    _ack(tail, initial)

    restarted = TailReader(str(logfile), str(dbfile))
    assert restarted.read_new_lines() == []
    with open(logfile, 'a', encoding='utf-8') as stream:
        stream.write('{"a": 3}\n')
    assert _lines(restarted.read_new_lines()) == ['{"a": 3}']


def test_same_event_line_has_stable_id_after_restart(tmp_path):
    logfile = tmp_path / 'log.jsonl'
    logfile.write_text('{"type":"port_scan","src":"9.9.9.9"}\n', encoding='utf-8')
    tail, dbfile = _tail(tmp_path, logfile)
    record = tail.read_new_lines()[0]
    restarted = TailReader(str(logfile), str(dbfile))
    replay = restarted.read_new_lines()[0]
    assert replay.event_id == record.event_id
    restarted.acknowledge(replay)
    assert TailReader(str(logfile), str(dbfile)).read_new_lines() == []


def test_rotation_restarts_at_new_file_start(tmp_path):
    logfile = tmp_path / 'log.jsonl'
    logfile.write_text('{"a": 1}\n', encoding='utf-8')
    tail, _ = _tail(tmp_path, logfile)
    first = tail.read_new_lines()
    _ack(tail, first)

    replacement = tmp_path / 'replacement.jsonl'
    replacement.write_text('{"b": 2}\n', encoding='utf-8')
    os.replace(replacement, logfile)
    rotated = tail.read_new_lines()
    assert _lines(rotated) == ['{"b": 2}']
    assert rotated[0].generation == first[0].generation + 1


def test_metadata_touch_does_not_replay_lines(tmp_path):
    logfile = tmp_path / 'log.jsonl'
    logfile.write_text('{"a": 1}\n{"a": 2}\n', encoding='utf-8')
    tail, _ = _tail(tmp_path, logfile)
    initial = tail.read_new_lines()
    _ack(tail, initial)
    os.utime(logfile, None)
    assert tail.read_new_lines() == []


def test_oversized_record_is_quarantined_and_following_line_processed(tmp_path, monkeypatch):
    import collector
    import sqlite3

    monkeypatch.setattr(collector, 'MAX_LINE_BYTES', 32)
    logfile = tmp_path / 'oversized.jsonl'
    logfile.write_bytes(b'x' * 40 + b'\n{"type":"port_scan"}\n')
    dbfile = tmp_path / 'oversized.sqlite'
    tail = TailReader(str(logfile), str(dbfile))
    SimHandler(str(logfile), tail=tail, db_file=str(dbfile)).drain()

    with sqlite3.connect(str(dbfile)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM ingestion_errors').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 1
