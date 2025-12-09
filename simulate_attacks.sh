#!/usr/bin/env bash
OUT="${1:-simulated_logs.jsonl}"
python - "$OUT" <<'PY'
import json, sys, time
out = sys.argv[1]
events = [
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"port_scan","src":"192.168.1.20","ports":[22,80,443]},
    {"type":"traffic_spike","bytes":12345678},
    {"type":"auth_failed","src":"10.0.0.6","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.6","message":"Failed password for invalid user"}
]
with open(out,'w') as f:
    for e in events:
        f.write(json.dumps(e) + '\n')
print('Wrote', out)
PY
