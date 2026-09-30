"""Write demo events to the durable JSONL collector or protected API."""
import argparse
import ipaddress
import json
import os
import sys
import time
from urllib.parse import urlsplit
from uuid import uuid4

from . import catalog
from security_config import SecretConfigurationError, load_ingest_token


def _event_with_id(event):
    result = dict(event)
    result.setdefault('event_id', str(uuid4()))
    return result


def write_jsonl(path, events=None, delay=0.0):
    """Append demo events, assigning a fresh stable ID to each written event."""
    events = events if events is not None else catalog.EVENTS
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    if os.path.exists(path) and os.path.getsize(path):
        with open(path, 'rb') as existing:
            existing.seek(-1, os.SEEK_END)
            needs_separator = existing.read(1) != b'\n'
        if needs_separator:
            with open(path, 'ab') as existing:
                existing.write(b'\n')

    with open(path, 'a', encoding='utf-8', newline='') as stream:
        for index, event in enumerate(events):
            stream.write(json.dumps(_event_with_id(event)) + '\n')
            stream.flush()
            if delay and index + 1 < len(events):
                time.sleep(delay)


def _is_loopback_url(url):
    parsed = urlsplit(url)
    if not parsed.hostname:
        return False
    if parsed.scheme == 'https':
        return True
    if parsed.scheme != 'http':
        return False
    if parsed.hostname.lower() == 'localhost':
        return True
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description='Write ThreatWatch demo events.')
    parser.add_argument('--target', choices=['file', 'ingest'], default='file',
                        help="'file' appends JSONL; 'ingest' POSTs to the protected API.")
    parser.add_argument('--scenario', choices=sorted(catalog.SCENARIOS), default='default',
                        help="Event catalog: 'default' demo set or 'spray' SOC-core scenario.")
    parser.add_argument('--out', default='simulated_logs.jsonl',
                        help='Output JSONL path for --target file.')
    parser.add_argument('--url', default='http://127.0.0.1:5000/api/ingest',
                        help='Ingest endpoint URL for --target ingest.')
    parser.add_argument('--delay', type=float, default=0.0,
                        help='Seconds to sleep between events.')
    args = parser.parse_args(argv)

    if args.delay < 0:
        parser.error('--delay must be non-negative')
    events = catalog.SCENARIOS.get(args.scenario, catalog.EVENTS)
    if args.target == 'file':
        write_jsonl(args.out, events=events, delay=args.delay)
        print(f'Wrote {len(events)} {args.scenario} events to', args.out)
        return 0
    try:
        token = load_ingest_token()
    except SecretConfigurationError as exc:
        print('ingest token configuration error:', exc, file=sys.stderr)
        return 2
    if not token:
        print('ingest mode requires INGEST_TOKEN or INGEST_TOKEN_FILE', file=sys.stderr)
        return 2
    if not _is_loopback_url(args.url):
        print('refusing to send bearer token over non-local HTTP; use HTTPS', file=sys.stderr)
        return 2

    import urllib.request

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, new_url):
            return None

    opener = urllib.request.build_opener(NoRedirectHandler)
    ok = fail = 0
    for index, event in enumerate(events):
        identified = _event_with_id(event)
        try:
            data = json.dumps(identified).encode('utf-8')
            req = urllib.request.Request(
                args.url, data=data,
                headers={
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
            )
            with opener.open(req, timeout=5) as response:
                response.read()
            ok += 1
        except Exception as exc:
            print('ingest failed for', event.get('type'), '->', type(exc).__name__, file=sys.stderr)
            fail += 1
        if args.delay and index + 1 < len(events):
            time.sleep(args.delay)
    print(f'Ingested {ok} events, {fail} failures')
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
