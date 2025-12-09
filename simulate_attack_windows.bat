@echo off
python - %1 <<PY
import json, sys
out = sys.argv[1] if len(sys.argv)>1 else 'simulated_logs.jsonl'
events = [
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"auth_failed","src":"10.0.0.5","message":"Failed password for invalid user"},
    {"type":"port_scan","src":"192.168.1.20","ports":[22,80,443]},
    {"type":"traffic_spike","bytes":12345678}
]
with open(out,'w') as f:
    for e in events:
        f.write(json.dumps(e) + '\\n')
print('Wrote', out)
PY
pause
