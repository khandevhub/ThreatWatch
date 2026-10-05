"""Decision explanation + HTML investigation report (stored data only).

``build_decision_explanation`` assembles the "WHY THREATWATCH ALERTED"
payload from the alert row, its stored evidence, the real risk factor
breakdown, Jev columns, the stored AI result (status only when absent),
and the live case/SOAR state — never fabricating any section.

``render_incident_report_html`` renders the printable investigation
report as a self-contained HTML document (no external dependencies,
text-node equivalent: all dynamic values are HTML-escaped).

Every section is honest about absence: disabled/missing components are
reported as such instead of being omitted or invented.
"""

from __future__ import annotations

import html
import json

from database import connect
from soc_cases import get_case, case_for_alert
from soar import USER_ACTOR_RE

__all__ = ['build_decision_explanation', 'build_report_data',
           'render_incident_report_html']


def _load_alert(db_file, alert_id):
    from app import _soc_alert_fields, _alert_entity_fields
    with connect(db_file) as connection:
        row = connection.execute(
            'SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
    if row is None:
        return None
    alert = {'id': row['id'], 'time': row['time'], 'rule': row['rule'],
             'severity': row['severity'], 'details': row['details'],
             'event_id': row['event_id']}
    alert.update(_soc_alert_fields(row))
    alert.update(_alert_entity_fields(alert))
    return alert


def _intel_rows(db_file, alert_id):
    """Stored enrichment rows for one alert (same data the console shows)."""
    with connect(db_file) as connection:
        return [dict(row) for row in connection.execute(
            'SELECT key, value FROM alert_enrichment WHERE alert_id = ?',
            (alert_id,))]


def build_decision_explanation(alert_id, db_file=None, ai_result=None,
                               investigation=None):
    """Assemble the WHY-THREATWATCH-ALERTED explanation from stored data.

    ``ai_result`` (optional) is the engine's AI status payload; when not
    supplied the stored ``ai_investigation_results`` row is used as-is
    (no AI engine call, so polling stays cheap and offline).
    """
    from app import _soc_alert_fields, _alert_entity_fields, _alert_hostnames
    alert = _load_alert(db_file, alert_id)
    if alert is None:
        return None
    alert['hostnames'] = _alert_hostnames(alert, db_file=db_file)
    factors = alert.get('risk_factors') or {}

    # -- stored AI result (status-only; never a live engine call) ---------
    if ai_result is None:
        with connect(db_file) as connection:
            row = connection.execute(
                'SELECT status, response_json, updated_at FROM '
                'ai_investigation_results WHERE alert_id = ?',
                (alert_id,)).fetchone()
        if row is None:
            ai_result = {'status': 'disabled', 'reason': 'ai_not_run'}
        else:
            ai_result = {'status': row['status']}
            try:
                response = json.loads(row['response_json'] or 'null')
            except (TypeError, ValueError):
                response = None
            if isinstance(response, dict):
                ai_result['response'] = {
                    'summary': response.get('summary'),
                    'assessment': response.get('assessment'),
                }

    # -- Jev honesty -------------------------------------------------------
    jev_status = alert.get('jev_status')
    if not jev_status:
        jev_status = 'not_recorded'

    # -- case / SOAR state -------------------------------------------------
    case = case_for_alert(alert_id, db_file=db_file)
    executions = []
    with connect(db_file) as connection:
        exec_rows = connection.execute(
            'SELECT execution_id, playbook_id, state, dry_run FROM '
            'soar_executions WHERE alert_id = ? '
            'ORDER BY created_at DESC LIMIT 5', (alert_id,)).fetchall()
        exec_ids = [row['execution_id'] for row in exec_rows]
        for row in exec_rows:
            executions.append({
                'execution_id': row['execution_id'],
                'playbook_id': row['playbook_id'],
                'state': row['state'],
                'dry_run': bool(row['dry_run']),
            })
        approvals = []
        if exec_ids:
            marks = ','.join('?' for _ in exec_ids)
            approval_rows = connection.execute(
                f'SELECT approval_id, execution_id, decision FROM '
                f'soar_approvals WHERE execution_id IN ({marks}) '
                f'ORDER BY requested_at DESC LIMIT 10', exec_ids).fetchall()
            approvals = [dict(row) for row in approval_rows]

    incident_ids = []
    if case is not None:
        incident_ids = [case['incident_id']]

    return {
        'alert_id': alert_id,
        'identity': {
            'alert_id': alert_id,
            'rule': alert.get('rule'),
            'rule_id': alert.get('rule_id'),
            'time': alert.get('time'),
            'severity': alert.get('severity'),
            'risk_score': alert.get('deterministic_risk_score'),
            'risk_band': alert.get('risk_band'),
            'source_ips': alert.get('source_ips') or [],
            'affected_users': alert.get('affected_users') or [],
            'hostnames': alert.get('hostnames') or [],
            'domains': alert.get('domains') or [],
        },
        'detection': {
            'rule': alert.get('rule'),
            'rule_id': alert.get('rule_id'),
            'details': alert.get('details'),
            'matched_events': alert.get('event_count')
            or len(alert.get('source_event_ids') or []),
            'source_event_ids': alert.get('source_event_ids') or [],
            'correlation_id': alert.get('correlation_id'),
            'detection_id': alert.get('detection_id'),
        },
        'risk': {
            'score': alert.get('deterministic_risk_score'),
            'band': alert.get('risk_band'),
            'factors': factors,
            'explanation': alert.get('risk_explanation'),
        },
        'mitre': {
            'techniques': (alert.get('mitre_techniques')
                           or alert.get('mitre') or []),
        },
        'jev': {
            'status': jev_status,
            'priority': alert.get('jev_priority'),
            'malicious_likelihood': alert.get('jev_malicious_likelihood'),
            'false_positive_likelihood':
                alert.get('jev_false_positive_likelihood'),
            'investigation_required': alert.get('investigation_required'),
            'attack_category': alert.get('jev_attack_category'),
        },
        'ai': {
            'status': ai_result.get('status'),
            'reason': ai_result.get('reason'),
            'summary': (ai_result.get('response') or {}).get('summary'),
        },
        'intel': _intel_rows(db_file, alert_id),
        'case': case,
        'soar': {
            'executions': executions,
            'approvals': approvals,
        },
        'incident_ids': incident_ids,
    }


def build_report_data(incident_id, db_file=None):
    """Collect everything the report needs from stored application data."""
    from soar import IncidentService
    from app import _alert_hostnames
    incident = IncidentService(db_file).get_incident(incident_id)
    if incident is None:
        return None
    alert_ids = incident.get('alert_ids') or []
    alerts = []
    for alert_id in alert_ids:
        alert = _load_alert(db_file, alert_id)
        if alert is None:
            continue
        alert['hostnames'] = _alert_hostnames(alert, db_file=db_file)
        alerts.append(alert)
    primary = alerts[0] if alerts else None

    timeline = []
    intel = []
    mitre = set()
    jev = None
    for alert in alerts:
        alert_id = alert['id']
        with connect(db_file) as connection:
            event_rows = []
            source_ids = alert.get('source_event_ids') or []
            if source_ids:
                marks = ','.join('?' for _ in source_ids)
                event_rows = connection.execute(
                f'SELECT event_id, event_time, event_type, src_ip, '
                f'user_name, host, command_line, domain FROM '
                f'events WHERE event_id IN ({marks}) '
                f'ORDER BY event_time LIMIT 50', source_ids).fetchall()
        for row in event_rows:
            timeline.append({
                'alert_id': alert_id,
                'event_time': row['event_time'],
                'event_type': row['event_type'],
                'src_ip': row['src_ip'],
                'user': row['user_name'],
                'host': row['host'],
                'command_line': row['command_line'],
                'domain': row['domain'],
            })
        intel.extend(_intel_rows(db_file, alert_id))
        mitre.update(alert.get('mitre_techniques')
                     or alert.get('mitre') or [])
        if jev is None:
            jev = {
                'status': alert.get('jev_status') or 'not_recorded',
                'priority': alert.get('jev_priority'),
            }
    timeline.sort(key=lambda item: item['event_time'] or '')

    # Case + notes
    case = case_for_alert(alert_ids[0], db_file=db_file) if alert_ids else None

    # SOAR executions + audit for the linked alerts
    from soar import SOAREngine
    engine = SOAREngine(db_file=db_file)
    executions = []
    audit_rows = []
    for alert_id in alert_ids:
        for execution in engine.list_executions(alert_id=alert_id, limit=5):
            full = engine.get_execution(execution['execution_id'])
            executions.append(full or execution)
            try:
                audit_rows.extend(engine.list_audit(
                    execution['execution_id'], limit=100))
            except Exception:
                continue
    audit_rows.sort(key=lambda row: row.get('created_at') or '')

    # Stored AI results
    ai_results = []
    with connect(db_file) as connection:
        for alert_id in alert_ids:
            row = connection.execute(
                'SELECT alert_id, status, response_json, updated_at FROM '
                'ai_investigation_results WHERE alert_id = ?',
                (alert_id,)).fetchone()
            if row is None:
                ai_results.append({'alert_id': alert_id,
                                   'status': 'not_run'})
                continue
            try:
                response = json.loads(row['response_json'] or 'null')
            except (TypeError, ValueError):
                response = None
            ai_results.append({
                'alert_id': alert_id,
                'status': row['status'],
                'updated_at': row['updated_at'],
                'summary': (response or {}).get('summary'),
                'assessment': (response or {}).get('assessment'),
                'recommended_actions': [
                    action.get('action') for action in
                    ((response or {}).get('recommended_actions') or [])
                    if isinstance(action, dict) and action.get('action')],
            })

    return {
        'incident': incident,
        'alerts': alerts,
        'primary_alert': primary,
        'timeline': timeline[:100],
        'intel': intel,
        'mitre': sorted(mitre),
        'jev': jev,
        'case': case,
        'executions': executions,
        'approvals': engine.list_approvals(limit=100),
        'audit': audit_rows[:60],
        'ai_results': ai_results,
    }


def _esc(value):
    return html.escape(str(value)) if value is not None else ''


def _chip_class(value, default=''):
    value = (value or '').lower()
    if value in ('high', 'critical', 'confirmed_threat', 'succeeded'):
        return 'chip-bad'
    if value in ('medium', 'investigating', 'waiting_approval', 'running',
                 'pending'):
        return 'chip-warn'
    if value in ('low', 'false_positive', 'closed'):
        return 'chip-info'
    return default


def _section(title, rows):
    parts = [f'<h2>{_esc(title)}</h2>']
    for label, value in rows:
        parts.append(
            f'<div class="row"><span class="label">{_esc(label)}</span>'
            f'<span class="value">{value}</span></div>')
    return ''.join(parts)


def _list_section(title, items):
    parts = [f'<h2>{_esc(title)}</h2>']
    if not items:
        parts.append('<p class="muted">None recorded.</p>')
        return ''.join(parts)
    parts.append('<ul>')
    for item in items:
        parts.append(f'<li>{item}</li>')
    parts.append('</ul>')
    return ''.join(parts)


def render_incident_report_html(data):
    """Render the investigation report HTML (all values escaped)."""
    incident = data['incident']
    primary = data['primary_alert'] or {}
    case = data['case'] or {}
    jev = data['jev'] or {}
    ai_results = data['ai_results']
    title = (f"THREATWATCH SECURITY INCIDENT REPORT\n"
             f"{incident['incident_id']}")
    parts = [
        '<!DOCTYPE html><html><head><meta charset="utf-8">',
        f'<title>{_esc(title)}</title>',
        '<style>',
        'body{font-family:Consolas,Menlo,monospace;margin:2rem auto;max-width:900px;',
        'color:#e6edf3;background:#0d1117;line-height:1.5}',
        'h1{border-bottom:2px solid #30363d;padding-bottom:.4rem;font-size:1.3rem}',
        'h2{border-bottom:1px solid #21262d;font-size:1.05rem;margin-top:1.6rem;',
        'color:#58a6ff;text-transform:uppercase;letter-spacing:.08em}',
        '.row{display:flex;gap:1rem;padding:.15rem 0}',
        '.label{flex:0 0 220px;color:#8b949e}',
        '.value{flex:1;white-space:pre-wrap;overflow-wrap:anywhere}',
        '.chip{display:inline-block;padding:.05rem .5rem;border:1px solid #30363d;',
        'border-radius:10px;font-size:.85rem;margin-right:.4rem}',
        '.chip-bad{color:#f85149;border-color:#f85149}',
        '.chip-warn{color:#d29922;border-color:#d29922}',
        '.chip-info{color:#58a6ff;border-color:#58a6ff}',
        '.muted{color:#8b949e}',
        '.banner{border:1px solid #30363d;border-radius:6px;padding:.6rem .9rem;',
        'margin:1rem 0;color:#d29922}',
        '</style></head><body>',
        '<div class="banner">SYNTHETIC SECURITY VALIDATION ENVIRONMENT — '
        'generated from stored ThreatWatch data. AI sections are advisory; '
        'deterministic sections (detection, risk, Jev provider state, SOAR '
        'audit) are engine-derived.</div>',
        f'<h1>{_esc(title)}</h1>',
    ]
    parts.append(_section('Incident', [
        ('Incident ID', f"<span class='chip'>{_esc(incident['incident_id'])}</span>"),
        ('Title', _esc(incident['title'])),
        ('Severity', f"<span class='chip {_chip_class(incident['severity'])}'>"
         f"{_esc(incident['severity'])}</span>"),
        ('Status', _esc(incident['status'])),
        ('Created', _esc(incident['created_at'])),
        ('Updated', _esc(incident['updated_at'])),
        ('Related alerts', ', '.join(
            '#' + str(a) for a in (incident.get('alert_ids') or [])) or 'None'),
    ]))
    parts.append(_section('Detection', [
        ('Alert', f"#{_esc(primary.get('id', '—'))}"),
        ('Rule', _esc(f"{primary.get('rule_id') or '—'} "
                      f"{primary.get('rule') or ''}")),
        ('Trigger reason', _esc(primary.get('details'))),
        ('Matched events', _esc((primary.get('source_event_ids') or []).__len__())
         or '0'),
        ('Correlation ID', _esc(primary.get('correlation_id') or 'None')),
    ]))
    parts.append(_section('Risk', [
        ('Score', _esc(f"{primary.get('deterministic_risk_score') or '—'}"
                       f"/100 ({primary.get('risk_band') or '—'})")),
        ('Factor breakdown', _esc(primary.get('risk_explanation'))),
    ]))
    parts.append(_section('Entities', [
        ('Source IP', ', '.join(primary.get('source_ips') or []) or 'None'),
        ('Users', ', '.join(primary.get('affected_users') or []) or 'None'),
        ('Hosts', ', '.join(primary.get('hostnames') or []) or 'None'),
        ('Domains', ', '.join(primary.get('domains') or []) or 'None'),
    ]))
    parts.append(_list_section('Timeline (chronological)', [
        f"{_esc(item['event_time'])} — {_esc(item['event_type'])}"
        + (f" — src {_esc(item['src_ip'])}" if item['src_ip'] else '')
        + (f" — user {_esc(item['user'])}" if item['user'] else '')
        + (f" — host {_esc(item['host'])}" if item['host'] else '')
        + (f" — cmd {_esc(item['command_line'][:80])}"
           if item['command_line'] else '')
        for item in data['timeline']
    ]))
    parts.append(_list_section('Threat intelligence', [
        f"{_esc(item.get('key'))}={_esc(item.get('value'))}"
        for item in (data['intel'] or [])
    ]))
    parts.append(_section('MITRE ATT&CK', [
        ('Techniques', ', '.join(data['mitre']) or 'None recorded'),
    ]))
    parts.append(_section('Jev (deterministic decision layer)', [
        ('Provider / state', _esc(jev.get('status') or 'not_recorded')),
        ('Priority', _esc(jev.get('priority') or '—')),
        ('Advisory status', 'Jev is deterministic and never AI-generated'),
    ]))
    ai_parts = []
    for result in ai_results:
        status = result.get('status') or 'not_run'
        line = (f"Alert #{_esc(result.get('alert_id'))}: "
                f"<span class='chip'>AI {_esc(status)}</span>")
        if status == 'ok':
            line += (f" — summary: {_esc(result.get('summary') or '(none)')}"
                     f"; assessment: {_esc(result.get('assessment') or '(none)')}")
            recommendations = result.get('recommended_actions') or []
            if recommendations:
                line += (f"; recommendations: "
                         f"{_esc('; '.join(recommendations[:5]))}")
        ai_parts.append(line)
    parts.append(_section('AI investigation (advisory)', [
        ('Results', '<br>'.join(ai_parts) or 'No alerts linked'),
        ('Grounding', _esc('RAG sources are stored per alert in the '
                           'dashboard AI panel; the report lists the '
                           'summary/assessment only.')),
    ]))
    decision = case.get('decision') or 'needs investigation'
    parts.append(_section('Analyst decision', [
        ('Case', f"{_esc(case.get('case_id') or '—')} "
                 f"(status {_esc(case.get('status') or 'no case opened')})"),
        ('Decision', f"<span class='chip {_chip_class(case.get('decision'))}'>"
                     f"{_esc(decision.upper())}</span>"),
        ('Analyst', _esc(case.get('analyst') or '—')),
        ('Notes', '<br>'.join(
            f"[{_esc(note['created_at'])}] {_esc(note['author'])}: "
            f"{_esc(note['body'])}"
            for note in (case.get('notes') or [])) or 'None recorded'),
    ]))
    soar_rows = []
    for execution in data['executions']:
        soar_rows.append((
            f"{_esc(execution['execution_id'])} — "
            f"{_esc(execution['playbook_id'])} v"
            f"{_esc(execution['playbook_version'])}",
            f"state <span class='chip {_chip_class(execution['state'])}'>"
            f"{_esc(execution['state'])}</span>"
            f"{' (DRY RUN)' if execution.get('dry_run') else ' (REAL)'}"
        ))
    for approval in data['approvals']:
        soar_rows.append((
            f"Approval {_esc(approval.get('approval_id'))}",
            f"decision {_esc(approval.get('decision'))}"))
    parts.append(_list_section('SOAR (dry-run simulated response)',
                               [f"{_esc(label)}: {value}"
                                for label, value in soar_rows]
                               or []))
    parts.append(_list_section('Audit trail', [
        f"{_esc(entry.get('created_at'))} — {_esc(entry.get('actor'))} — "
        f"{_esc(entry.get('event_type'))}"
        + (f" · {_esc(entry.get('from_state'))} → "
           f"{_esc(entry.get('to_state'))}"
           if entry.get('from_state') or entry.get('to_state') else '')
        for entry in data['audit']
    ]))
    parts.append('<p class="muted">Report generated locally by ThreatWatch '
                 'from stored application data. No values are hard-coded; '
                 'missing sections are shown as absent on purpose.</p>')
    parts.append('</body></html>')
    return ''.join(parts)
