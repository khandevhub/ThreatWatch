"""Collector tail-reader tests (incremental appends, no duplicate processing)."""
import pytest

from collector import TailReader


def test_reads_only_newly_appended_lines(tmp_path):
    f = tmp_path / 'log.jsonl'
    f.write_text('{"a": 1}\n', encoding='utf-8')
    tail = TailReader(str(f))
    assert tail.read_new_lines() == ['{"a": 1}']  # initial read: whole small file
    with open(f, 'a', encoding='utf-8') as fh:
        fh.write('{"a": 2}\n{"a": 3}\n')
    assert tail.read_new_lines() == ['{"a": 2}', '{"a": 3}']
    assert tail.read_new_lines() == []  # nothing new


def test_large_preexisting_file_starts_at_end(tmp_path):
    f = tmp_path / 'big.jsonl'
    f.write_text('{"old": 1}\n' * 50000, encoding='utf-8')
    # explicit small cap: proves the seek-to-end path for pre-existing content
    tail = TailReader(str(f), max_initial_read=10)
    assert tail.read_new_lines() == []
    with open(f, 'a', encoding='utf-8') as fh:
        fh.write('{"new": 2}\n')
    assert tail.read_new_lines() == ['{"new": 2}']


def test_truncation_is_detected(tmp_path):
    f = tmp_path / 'log.jsonl'
    f.write_text('{"a": 1}\n', encoding='utf-8')
    tail = TailReader(str(f))
    tail.read_new_lines()
    with open(f, 'w', encoding='utf-8') as fh:  # rewrite (truncate) the file
        fh.write('{"b": 9}\n')
    lines = tail.read_new_lines()
    assert lines == ['{"b": 9}']


def test_same_size_rewrite_is_detected(tmp_path):
    f = tmp_path / 'log.jsonl'
    f.write_text('{"a": 1}\n', encoding='utf-8')
    tail = TailReader(str(f))
    assert tail.read_new_lines() == ['{"a": 1}']
    # same-length rewrite: 9 bytes in, 9 bytes out
    with open(f, 'w', encoding='utf-8') as fh:
        fh.write('{"z": 9}\n')
    assert tail.read_new_lines() == ['{"z": 9}']


def test_partial_line_is_held_until_complete(tmp_path):
    f = tmp_path / 'log.jsonl'
    with open(f, 'w', encoding='utf-8') as fh:
        fh.write('{"partial": ')
    tail = TailReader(str(f))
    assert tail.read_new_lines() == []
    with open(f, 'a', encoding='utf-8') as fh:
        fh.write('1}\n')
    assert tail.read_new_lines() == ['{"partial": 1}']


def test_duplicate_processing_regression(tmp_path):
    """Appending the same event twice processes it twice; re-reading must not."""
    f = tmp_path / 'log.jsonl'
    f.write_text('{"a": 1}\n', encoding='utf-8')
    tail = TailReader(str(f))
    first = tail.read_new_lines()
    with open(f, 'a', encoding='utf-8') as fh:
        fh.write('{"a": 2}\n')
    second = tail.read_new_lines()
    assert first == ['{"a": 1}']
    assert second == ['{"a": 2}']
    # the crux: no-change reads must never re-emit the previous lines
    assert tail.read_new_lines() == []
    assert tail.read_new_lines() == []


def test_no_duplicate_burst_when_mtime_changes_without_size_change(tmp_path):
    """Regression: a metadata-only touch at unchanged size re-emitted old lines."""
    f = tmp_path / 'log.jsonl'
    f.write_text('{"a": 1}\n{"a": 2}\n', encoding='utf-8')
    tail = TailReader(str(f))
    assert tail.read_new_lines() == ['{"a": 1}', '{"a": 2}']
    # simulate a spurious watchdog event: touch mtime, no size change
    import os
    os.utime(f, None)
    assert tail.read_new_lines() == []
    assert tail.read_new_lines() == []
