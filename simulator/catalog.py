# simulator/catalog.py - the demo event sets, shared by shell/batch/CLI writers
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

# Phase 2 SOC-core scenario: password spraying across four accounts from one
# source, then a PowerShell download cradle on an endpoint.
SPRAY_EVENTS = [
    {"type": "auth_failed", "src": "203.0.113.7", "user": "alice"},
    {"type": "auth_failed", "src": "203.0.113.7", "user": "bob"},
    {"type": "auth_failed", "src": "203.0.113.7", "user": "carol"},
    {"type": "auth_failed", "src": "203.0.113.7", "user": "dave"},
    {"type": "auth_failed", "src": "203.0.113.7", "user": "alice"},
    {"type": "auth_failed", "src": "203.0.113.7", "user": "bob"},
    {"type": "auth_failed", "src": "203.0.113.7", "user": "carol"},
    {"type": "auth_failed", "src": "203.0.113.7", "user": "dave"},
    {"event_type": "powershell_script", "host": "workstation-12", "user": "alice",
     "command_line": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAGsAaQBsAGwA"},
]

SCENARIOS = {
    'default': EVENTS,
    'spray': SPRAY_EVENTS,
}


def events_jsonl(scenario='default'):
    """Return the demo events as a JSONL string (one JSON object per line)."""
    events = SCENARIOS.get(scenario, EVENTS)
    return "".join(json.dumps(e) + "\n" for e in events)
