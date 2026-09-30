# simulator/catalog.py - the demo event set, shared by shell/batch/CLI writers
import json

EVENTS = [
    {"type": "auth_failed", "src": "10.0.0.5", "message": "Failed password for invalid user"},
    {"type": "auth_failed", "src": "10.0.0.5", "message": "Failed password for invalid user"},
    {"type": "auth_failed", "src": "10.0.0.5", "message": "Failed password for invalid user"},
    {"type": "auth_failed", "src": "10.0.0.5", "message": "Failed password for invalid user"},
    {"type": "auth_failed", "src": "10.0.0.5", "message": "Failed password for invalid user"},
    {"type": "port_scan", "src": "10.0.0.6", "ports": [22, 80, 443]},
    {"type": "traffic_spike", "bytes": 12345678},
]


def events_jsonl():
    """Return the demo events as a JSONL string (one JSON object per line)."""
    return "".join(json.dumps(e) + "\n" for e in EVENTS)
