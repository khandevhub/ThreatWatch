"""Simulator JSONL append behavior tests."""
import json

from simulator.append_events import write_jsonl


def test_writer_separates_events_from_existing_partial_line(tmp_path):
    logfile = tmp_path / 'simulated.jsonl'
    logfile.write_bytes(b'{"partial":')

    write_jsonl(str(logfile), events=[{'type': 'port_scan', 'src': '9.9.9.9'}])

    lines = logfile.read_bytes().splitlines()
    assert lines[0] == b'{"partial":'
    event = json.loads(lines[1])
    assert event['type'] == 'port_scan'
    assert event['src'] == '9.9.9.9'
    assert event['event_id']
