# simulator/append_events.py - shared logic for writing demo events
import argparse
import json
import os
import sys

from . import catalog


def write_jsonl(path, events=None):
    """Write (or append) demo events to a JSONL file."""
    events = events if events is not None else catalog.EVENTS
    mode = 'a' if os.path.exists(path) else 'w'
    with open(path, mode, encoding='utf-8') as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Write ThreatWatch demo events.")
    parser.add_argument('--target', choices=['file', 'ingest'], default='file',
                        help="'file' writes simulated_logs.jsonl (default); "
                             "'ingest' POSTs each event to the ingest endpoint.")
    parser.add_argument('--out', default='simulated_logs.jsonl',
                        help="Output JSONL path for --target file.")
    parser.add_argument('--url', default='http://127.0.0.1:5000/api/ingest',
                        help="Ingest endpoint URL for --target ingest.")
    parser.add_argument('--token', default=os.environ.get('INGEST_TOKEN', ''),
                        help="Bearer token for the ingest endpoint (or set INGEST_TOKEN).")
    parser.add_argument('--delay', type=float, default=0.0,
                        help="Seconds to sleep between events.")
    args = parser.parse_args(argv)

    if args.target == 'file':
        write_jsonl(args.out)
        print("Wrote demo events to", args.out)
        return 0

    # ingest mode: POST each event to the running collector/app
    import urllib.request
    ok = fail = 0
    for e in catalog.EVENTS:
        try:
            data = json.dumps(e).encode('utf-8')
            req = urllib.request.Request(
                args.url, data=data,
                headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
            if args.token:
                req.add_header('Authorization', 'Bearer ' + args.token)
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
            ok += 1
        except Exception as exc:
            print("ingest failed for", e.get('type'), "->", exc, file=sys.stderr)
            fail += 1
        if args.delay:
            import time
            time.sleep(args.delay)
    print(f"Ingested {ok} events, {fail} failures")
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
