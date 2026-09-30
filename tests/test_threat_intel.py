"""Threat-intel enrichment tests."""
import sqlite3

import pytest

import detector as detector_module


@pytest.fixture()
def detector(tmp_path, monkeypatch):
    dbfile = tmp_path / 'test_db.sqlite'
    monkeypatch.setenv('DB_FILE', str(dbfile))
    intel = tmp_path / 'intel.csv'
    intel.write_text("ip,tag\n9.9.9.9,known_scanner\n", encoding='utf-8')
    monkeypatch.setenv('THREAT_INTEL', str(intel))
    # bind module constants explicitly (import-time constants otherwise
    # leak the repo CSV/DB into every test)
    detector_module.DB = str(dbfile)
    detector_module.bad_ips = detector_module.load_threat_intel(str(intel))
    detector_module.failed_logins.clear()
    detector_module.init_db()
    yield detector_module
    detector_module.failed_logins.clear()


def _alerts_and_enrichment(dbfile):
    conn = sqlite3.connect(str(dbfile))
    try:
        alerts = conn.execute(
            'SELECT rule, severity, details FROM alerts ORDER BY id DESC').fetchall()
        enrichment = conn.execute(
            'SELECT key, value FROM alert_enrichment ORDER BY id').fetchall()
        return alerts, dict(enrichment)
    finally:
        conn.close()


def test_bruteforce_from_known_ip_is_enriched(detector, tmp_path):
    for _ in range(5):
        detector.process_event({'type': 'auth_failed', 'src': '9.9.9.9'})
    alerts, enrichment = _alerts_and_enrichment(tmp_path / 'test_db.sqlite')
    assert alerts and alerts[0][0] == 'BRUTE_FORCE'
    assert 'KNOWN_SCANNER' in alerts[0][2]          # visible in the alert text
    assert enrichment.get('known_threat') == 'true'  # structured enrichment row
    assert enrichment.get('source_ip') == '9.9.9.9'


def test_port_scan_from_known_ip_is_enriched(detector, tmp_path):
    detector.process_event({'type': 'port_scan', 'src': '9.9.9.9', 'ports': [22, 80]})
    alerts, enrichment = _alerts_and_enrichment(tmp_path / 'test_db.sqlite')
    assert alerts and alerts[0][0] == 'PORT_SCAN'
    assert 'KNOWN_SCANNER' in alerts[0][2]
    assert enrichment.get('known_threat') == 'true'


def test_bruteforce_from_unknown_ip_has_no_threat_tag(detector, tmp_path):
    for _ in range(5):
        detector.process_event({'type': 'auth_failed', 'src': '1.2.3.4'})
    alerts, enrichment = _alerts_and_enrichment(tmp_path / 'test_db.sqlite')
    assert alerts and alerts[0][0] == 'BRUTE_FORCE'
    assert 'KNOWN' not in alerts[0][2]
    assert enrichment.get('known_threat') == 'false'


def test_intel_file_with_header_only_loads_cleanly(tmp_path):
    intel = tmp_path / 'empty.csv'
    intel.write_text('ip,tag\n', encoding='utf-8')
    assert detector_module.load_threat_intel(str(intel)) == {}


def test_intel_loader_tolerates_utf8_bom(tmp_path):
    intel = tmp_path / 'bom.csv'
    intel.write_bytes(b'\xef\xbb\xbfip,tag\n9.9.9.9,known_scanner\n')
    assert detector_module.load_threat_intel(str(intel)) == {'9.9.9.9': 'known_scanner'}
