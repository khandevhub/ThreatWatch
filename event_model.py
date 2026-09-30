"""Validated event contract for simulator and future telemetry adapters."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = 1
EVENT_FAMILIES = frozenset({
    'authentication', 'process', 'network', 'dns', 'web', 'powershell',
    'endpoint', 'cloud_identity', 'simulator',
})
EVENT_FAMILY_BY_TYPE = {
    'auth_failed': 'authentication',
    'auth_success': 'authentication',
    'port_scan': 'network',
    'traffic_spike': 'network',
    'process_start': 'process',
    'dns_query': 'dns',
    'web_request': 'web',
    'powershell_script': 'powershell',
}
MAX_METADATA_BYTES = 64 * 1024


class EventValidationError(ValueError):
    """Raised when an incoming object violates the normalized event contract."""


def _utc_now():
    return datetime.now(timezone.utc)


def _text(value, field_name, *, required=False, limit=4096):
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise EventValidationError(f'{field_name} must be a string')
    value = value.strip()
    if required and not value:
        raise EventValidationError(f'{field_name} is required')
    if len(value) > limit:
        raise EventValidationError(f'{field_name} exceeds {limit} characters')
    if any(ord(char) < 32 and char not in '\t\n\r' for char in value):
        raise EventValidationError(f'{field_name} contains control characters')
    return value or ('' if required else None)


def _timestamp(value, field_name):
    if value is None:
        value = _utc_now()
    elif isinstance(value, str):
        candidate = value.strip()
        if candidate.endswith('Z'):
            candidate = candidate[:-1] + '+00:00'
        try:
            value = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise EventValidationError(f'{field_name} must be an ISO-8601 timestamp') from exc
    if not isinstance(value, datetime):
        raise EventValidationError(f'{field_name} must be an ISO-8601 timestamp')
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _ip(value, field_name):
    if value is None:
        return None
    text = _text(value, field_name, required=True, limit=64)
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError as exc:
        raise EventValidationError(f'{field_name} must be an IP address') from exc


def _port(value, field_name):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise EventValidationError(f'{field_name} must be an integer from 1 to 65535')
    return value


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    schema_version: int
    event_time: str
    ingestion_time: str
    source: str
    source_type: str
    event_type: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    action: str | None = None
    outcome: str | None = None
    process: str | None = None
    command_line: str | None = None
    domain: str | None = None
    url: str | None = None
    file_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload, *, default_source='unknown', generated_event_id=None):
        if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
            raise EventValidationError('event must be a JSON object with string keys')

        allowed = {
            'event_id', 'schema_version', 'event_time', 'ingestion_time', 'source',
            'source_type', 'host', 'user', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'event_type', 'action', 'outcome', 'process', 'command_line', 'domain',
            'url', 'file_hash', 'metadata',
            # Legacy simulator fields accepted during the foundation migration.
            'type', 'time', 'src', 'ports', 'bytes', 'message',
        }
        unknown = set(payload) - allowed
        if unknown:
            raise EventValidationError(f'unsupported event fields: {", ".join(sorted(unknown))}')

        version = payload.get('schema_version', SCHEMA_VERSION)
        if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
            raise EventValidationError(f'unsupported schema_version: {version!r}')

        event_type_value = payload.get('event_type', payload.get('type'))
        if 'event_type' in payload and 'type' in payload and payload['event_type'] != payload['type']:
            raise EventValidationError('event_type and legacy type disagree')
        event_type = _text(event_type_value, 'event_type', required=True, limit=128)
        if 'event_id' in payload:
            event_id = payload['event_id']
        else:
            event_id = generated_event_id or str(uuid4())
        event_id = _text(event_id, 'event_id', required=True, limit=128)
        if any(ord(char) < 33 for char in event_id):
            raise EventValidationError('event_id contains whitespace or control characters')

        source = _text(payload.get('source', default_source), 'source', required=True, limit=256)
        source_type = payload.get('source_type', EVENT_FAMILY_BY_TYPE.get(event_type, 'endpoint'))
        source_type = _text(source_type, 'source_type', required=True, limit=64)
        if source_type not in EVENT_FAMILIES:
            raise EventValidationError(f'unsupported source_type: {source_type}')

        src_ip_value = payload.get('src_ip', payload.get('src'))
        if 'src_ip' in payload and 'src' in payload and payload['src_ip'] != payload['src']:
            raise EventValidationError('src_ip and legacy src disagree')
        src_port = _port(payload.get('src_port'), 'src_port')
        dst_port = _port(payload.get('dst_port'), 'dst_port')
        metadata = payload.get('metadata', {})
        if not isinstance(metadata, dict) or any(not isinstance(key, str) for key in metadata):
            raise EventValidationError('metadata must be a JSON object with string keys')
        metadata = dict(metadata)
        if 'ports' in payload:
            ports = payload['ports']
            if not isinstance(ports, list) or len(ports) > 256:
                raise EventValidationError('ports must be a list of at most 256 port numbers')
            metadata['ports'] = [_port(port, 'ports item') for port in ports]
        if 'bytes' in payload:
            byte_count = payload['bytes']
            if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
                raise EventValidationError('bytes must be a non-negative integer')
            metadata['bytes'] = byte_count
        if 'message' in payload:
            metadata['message'] = _text(payload['message'], 'message', limit=8192)
        try:
            metadata_bytes = json.dumps(metadata, ensure_ascii=False, allow_nan=False).encode('utf-8')
        except (TypeError, ValueError) as exc:
            raise EventValidationError('metadata must contain JSON-compatible values') from exc
        if len(metadata_bytes) > MAX_METADATA_BYTES:
            raise EventValidationError('metadata exceeds 65536 bytes')

        action = payload.get('action')
        outcome = payload.get('outcome')
        if event_type == 'auth_failed':
            if action is None:
                action = 'login'
            if outcome is None:
                outcome = 'failure'
        if ('event_time' in payload and 'time' in payload
                and payload['event_time'] is not None and payload['time'] is not None
                and payload['event_time'] != payload['time']):
            raise EventValidationError('event_time and legacy time disagree')
        event_time = payload.get('event_time')
        if event_time is None:
            event_time = payload.get('time')
        return cls(
            event_id=event_id,
            schema_version=SCHEMA_VERSION,
            event_time=_timestamp(event_time, 'event_time'),
            ingestion_time=_timestamp(None, 'ingestion_time'),
            source=source,
            source_type=source_type,
            event_type=event_type,
            host=_text(payload.get('host'), 'host', limit=256),
            user=_text(payload.get('user'), 'user', limit=256),
            src_ip=_ip(src_ip_value, 'src_ip'),
            dst_ip=_ip(payload.get('dst_ip'), 'dst_ip'),
            src_port=src_port,
            dst_port=dst_port,
            action=_text(action, 'action', limit=128),
            outcome=_text(outcome, 'outcome', limit=128),
            process=_text(payload.get('process'), 'process', limit=1024),
            command_line=_text(payload.get('command_line'), 'command_line', limit=8192),
            domain=_text(payload.get('domain'), 'domain', limit=253),
            url=_text(payload.get('url'), 'url', limit=8192),
            file_hash=_text(payload.get('file_hash'), 'file_hash', limit=256),
            metadata=metadata,
        )

    def to_dict(self):
        return asdict(self)
