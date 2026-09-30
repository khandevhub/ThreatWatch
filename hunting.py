"""Threat-hunting query layer (Phase 3D).

Safe, bounded, deterministic search over stored events and alert linkage.
Every filter is whitelisted and every query is parameterized — user input
never becomes SQL, and LIKE wildcards in substring filters are escaped so
semantics stay predictable. Results are ordered by (event_time, event_id)
and hard-capped, so no query can return unbounded data or run arbitrary SQL.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import re
import sqlite3
from urllib.parse import unquote_plus

from database import DB, connect
from evidence import redact_text

MAX_LIMIT = 500
DEFAULT_LIMIT = 100

# Exact-match columns (validated before use).
EXACT_FILTERS = ('src_ip', 'dst_ip', 'event_type', 'file_hash')
# Substring columns (LIKE, wildcards escaped).
SUBSTRING_FILTERS = ('user', 'host', 'process', 'command', 'domain', 'url')
TIME_FILTERS = ('time_from', 'time_to')
# Linkage filters resolved through alerts, not the events table.
LINK_FILTERS = ('alert_id', 'correlation_id', 'technique')

ALLOWED_FILTERS = frozenset(EXACT_FILTERS + SUBSTRING_FILTERS + TIME_FILTERS + LINK_FILTERS)

# Hunt-filter name -> events-table column. Column names are never user input;
# only whitelisted keys reach this map.
FILTER_COLUMN = {
    'src_ip': 'src_ip', 'dst_ip': 'dst_ip', 'event_type': 'event_type',
    'file_hash': 'file_hash', 'user': 'user_name', 'host': 'host',
    'process': 'process', 'command': 'command_line', 'domain': 'domain',
    'url': 'url',
}

_TECHNIQUE_PATTERN = re.compile(r'^T\d{4}(?:\.\d{3})?$')
_IDENTIFIER_PATTERN = re.compile(r'^[\w.:\-/@ ]{1,256}$')


class HuntError(ValueError):
    """A hunt request was malformed (unknown filter, bad value, bad paging)."""


def _escape_like(value):
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def _validate_ip(name, raw):
    try:
        return ipaddress.ip_address(raw.strip()).compressed
    except ValueError:
        raise HuntError(f'{name} must be a valid IP address') from None


def _validate_time(name, raw):
    text = raw.strip()
    # Normalized event timestamps look like 2025-01-01T00:00:00.000000Z;
    # accept any prefix of that (date, datetime with/without Z). Shape AND
    # semantic bounds are validated so impossible dates fail closed.
    match = re.match(
        r'^(\d{4})-(\d{2})-(\d{2})'
        r'(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?'
        r'(Z|[+-]\d{2}:?\d{2})?$', text)
    if match is None:
        raise HuntError(f'{name} must be an ISO-8601 timestamp or date')
    year, month, day = (int(match.group(index)) for index in (1, 2, 3))
    try:
        datetime.date(year, month, day)
    except ValueError:
        raise HuntError(f'{name} must be a real calendar date') from None
    if match.group(4) is not None and int(match.group(4)) > 23:
        raise HuntError(f'{name} hour must be 00-23')
    if match.group(5) is not None and int(match.group(5)) > 59:
        raise HuntError(f'{name} minute must be 00-59')
    if match.group(6) is not None and int(match.group(6)) > 59:
        raise HuntError(f'{name} second must be 00-59')
    if ' ' in text:
        text = text.replace(' ', 'T', 1)
    return text


def parse_hunt_filters(raw_args):
    """Validate raw filter key/values into (clauses, params, link_filters).

    Unknown filter names fail closed. Substring filters are escaped for LIKE.
    Linkage filters are returned separately; they need alert-table lookups.
    """
    if not isinstance(raw_args, dict):
        raise HuntError('filters must be a mapping')
    clauses, params = [], []
    link = {}
    for key in sorted(raw_args):
        raw = raw_args[key]
        if raw is None or raw == '':
            continue
        if key not in ALLOWED_FILTERS:
            raise HuntError(f'unknown filter: {key}')
        value = unquote_plus(str(raw)).strip()
        if not value or len(value) > 256:
            raise HuntError(f'{key} value must be 1-256 characters')
        if key in EXACT_FILTERS:
            if key in ('src_ip', 'dst_ip'):
                value = _validate_ip(key, value)
            elif key == 'file_hash':
                if not re.match(r'^[0-9a-fA-F]{32,128}$', value):
                    raise HuntError('file_hash must be a hexadecimal hash')
            clauses.append(f'{FILTER_COLUMN[key]} = ?')
            params.append(value)
        elif key in SUBSTRING_FILTERS:
            if not _IDENTIFIER_PATTERN.match(value):
                raise HuntError(f'{key} contains unsupported characters')
            clauses.append(f'{FILTER_COLUMN[key]} LIKE ? ESCAPE \'\\\'')
            params.append('%' + _escape_like(value) + '%')
        elif key in TIME_FILTERS:
            clauses.append(f'event_time >= ?' if key == 'time_from' else 'event_time <= ?')
            params.append(_validate_time(key, value))
        elif key == 'alert_id':
            if not re.match(r'^\d{1,10}$', value):
                raise HuntError('alert_id must be a positive integer')
            link['alert_id'] = int(value)
        elif key == 'correlation_id':
            if not re.match(r'^[0-9a-fA-F-]{8,64}$', value):
                raise HuntError('correlation_id must be a UUID-like identifier')
            link['correlation_id'] = value
        elif key == 'technique':
            if not _TECHNIQUE_PATTERN.match(value.upper()):
                raise HuntError('technique must look like T1110 or T1059.001')
            link['technique'] = value.upper()
    return clauses, params, link


def _linked_event_ids(connection, link):
    """Resolve alert-based filters to event IDs (all parameterized).

    Returns None when no link filters were given; a set (possibly empty)
    otherwise. An unknown alert_id yields an empty set, never "unfiltered".
    """
    id_sets = []
    if 'alert_id' in link:
        row = connection.execute(
            'SELECT source_event_ids_json, event_id FROM alerts WHERE id = ?',
            (link['alert_id'],)).fetchone()
        if row is None:
            return set()
        try:
            ids = set(json.loads(row['source_event_ids_json'] or '[]'))
        except (TypeError, ValueError):
            ids = set()
        if row['event_id']:
            ids.add(row['event_id'])
        id_sets.append(ids)
    if 'correlation_id' in link:
        rows = connection.execute(
            'SELECT source_event_ids_json, event_id FROM alerts '
            'WHERE correlation_id = ? LIMIT 500',
            (link['correlation_id'],)).fetchall()
        ids = set()
        for row in rows:
            try:
                ids.update(json.loads(row['source_event_ids_json'] or '[]'))
            except (TypeError, ValueError):
                pass
            if row['event_id']:
                ids.add(row['event_id'])
        if not ids:
            return set()
        id_sets.append(ids)
    if 'technique' in link:
        # Stored ATT&CK mappings live in mitre_techniques_json; the technique
        # value is regex-validated, and the LIKE pattern is parameterized.
        technique_pattern = '%"' + link['technique'] + '"%'
        rows = connection.execute(
            'SELECT source_event_ids_json, event_id FROM alerts '
            'WHERE mitre_techniques_json LIKE ? LIMIT 500',
            (technique_pattern,)).fetchall()
        ids = set()
        for row in rows:
            try:
                ids.update(json.loads(row['source_event_ids_json'] or '[]'))
            except (TypeError, ValueError):
                pass
            if row['event_id']:
                ids.add(row['event_id'])
        if not ids:
            return set()
        id_sets.append(ids)
    if not id_sets:
        return None
    combined = set(id_sets[0])
    for extra in id_sets[1:]:
        combined &= extra
    return combined


def _safe_event_view(row):
    """Bounded, secret-safe event view for hunt results."""
    get = row.get if hasattr(row, 'get') else (lambda key, r=row: r[key] if key in r.keys() else None)
    metadata = get('metadata_json')
    view = {
        'event_id': get('event_id'),
        'event_time': get('event_time'),
        'ingestion_time': get('ingestion_time'),
        'source': get('source'),
        'source_type': get('source_type'),
        'event_type': get('event_type'),
        'host': get('host'),
        'user': get('user_name'),
        'src_ip': get('src_ip'),
        'dst_ip': get('dst_ip'),
        'src_port': get('src_port'),
        'dst_port': get('dst_port'),
        'action': get('action'),
        'outcome': get('outcome'),
        'process': get('process'),
        'command_line': redact_text(get('command_line'), 512),
        'domain': get('domain'),
        'url': redact_text(get('url'), 512),
        'file_hash': get('file_hash'),
    }
    if metadata:
        try:
            parsed = json.loads(metadata)
            if isinstance(parsed, dict):
                view['metadata'] = {
                    key: redact_text(str(value), 256)
                    for key, value in sorted(parsed.items())
                    if isinstance(key, str) and key in ('ports', 'bytes', 'message')
                }
        except (TypeError, ValueError):
            view['metadata'] = None
    return view


def hunt(filters, db_file=None, limit=DEFAULT_LIMIT, offset=0):
    """Run a bounded, deterministic hunt over stored events."""
    clauses, params, link = parse_hunt_filters(filters)
    try:
        limit_i = int(limit)
        offset_i = int(offset)
    except (TypeError, ValueError):
        raise HuntError('limit and offset must be integers') from None
    if limit_i < 1 or limit_i > MAX_LIMIT:
        raise HuntError(f'limit must be between 1 and {MAX_LIMIT}')
    if offset_i < 0:
        raise HuntError('offset must be non-negative')

    with connect(db_file or DB) as connection:
        connection.row_factory = sqlite3.Row
        linked = _linked_event_ids(connection, link)
        if linked is not None and not linked:
            return {'total': 0, 'limit': limit_i, 'offset': offset_i, 'results': []}
        if linked:
            ids = sorted(linked)[:MAX_LIMIT]
            placeholders = ','.join('?' for _ in ids)
            clauses = clauses + [f'event_id IN ({placeholders})']
            params = params + ids
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        total = connection.execute(
            f'SELECT COUNT(*) FROM events{where}', tuple(params)).fetchone()[0]
        rows = connection.execute(
            f'SELECT * FROM events{where} '
            f'ORDER BY event_time, event_id LIMIT ? OFFSET ?',
            tuple(params) + (limit_i, offset_i)).fetchall()
    results = [_safe_event_view(dict(row)) for row in rows]
    return {'total': total, 'limit': limit_i, 'offset': offset_i, 'results': results}
