"""SOC threat-intelligence: classification, structured enrichment, tolerance."""
import pytest

from threat_intel import Enrichment, ThreatIntel, classify_indicator


@pytest.fixture()
def intel(tmp_path):
    feed = tmp_path / 'intel.csv'
    feed.write_text(
        'ip,tag,confidence,source\n'
        '9.9.9.9,known_scanner,0.95,unit-test\n'
        '2001:db8::5,known_scanner,\n'
        'evil.example.com,phishing_domain,0.8,\n'
        'https://bad.example.net/payload,drop_url,0.9,\n'
        'd41d8cd98f00b204e9800998ecf8427e,malware_md5,0.7,\n'
        + ('a' * 64) + ',malware_sha256,\n',
        encoding='utf-8')
    table = ThreatIntel()
    table.load_csv(str(feed))
    return table


def test_classify_indicator_types():
    assert classify_indicator('192.168.1.20') == 'ip'
    assert classify_indicator('2001:db8::1') == 'ip'
    assert classify_indicator('https://a.b/c') == 'url'
    assert classify_indicator('http://a.b') == 'url'
    assert classify_indicator('a' * 64) == 'hash'
    assert classify_indicator('a' * 32) == 'hash'
    assert classify_indicator('a' * 40) == 'hash'
    assert classify_indicator('a' * 128) == 'hash'
    assert classify_indicator('sub.domain.example') == 'domain'
    assert classify_indicator('not a domain') is None
    assert classify_indicator('') is None
    assert classify_indicator(None) is None


def test_legacy_ip_tag_csv_still_loads(tmp_path):
    feed = tmp_path / 'legacy.csv'
    feed.write_text('ip,tag\n192.168.1.20,known_scanner\n', encoding='utf-8')
    table = ThreatIntel()
    assert table.load_csv(str(feed)) == 1
    enrichment = table.lookup('192.168.1.20')
    assert enrichment.known_malicious and enrichment.confidence == 0.5
    assert enrichment.source == 'local_csv'


def test_known_ip_enrichment_is_structured(intel):
    enrichment = intel.lookup('9.9.9.9')
    assert isinstance(enrichment, Enrichment)
    assert enrichment.indicator == '9.9.9.9'
    assert enrichment.indicator_type == 'ip'
    assert enrichment.known_malicious is True
    assert enrichment.confidence == 0.95
    assert enrichment.source == 'unit-test'
    assert enrichment.to_dict()['known_malicious'] is True


def test_ipv6_domain_url_hash_enrichment(intel):
    assert intel.lookup('2001:db8::5').known_malicious is True
    assert intel.lookup('2001:db8::6').known_malicious is False
    domain = intel.lookup('evil.example.com')
    assert domain.known_malicious and domain.indicator_type == 'domain'
    url = intel.lookup('https://bad.example.net/payload')
    assert url.known_malicious and url.indicator_type == 'url'
    md5 = intel.lookup('d41d8cd98f00b204e9800998ecf8427e')
    assert md5.known_malicious and md5.indicator_type == 'hash'
    sha = intel.lookup('a' * 64)
    assert sha.known_malicious and sha.confidence == 0.5  # blank confidence


def test_unknown_indicator_yields_negative_enrichment(intel):
    enrichment = intel.lookup('8.8.8.8')
    assert enrichment.known_malicious is False
    assert enrichment.confidence == 0.0
    assert enrichment.source == 'none'


def test_malformed_indicator_returns_none(intel):
    assert intel.lookup('not a domain') is None
    assert intel.lookup('') is None
    assert intel.lookup(None) is None


def test_malformed_csv_rows_are_skipped(tmp_path):
    feed = tmp_path / 'broken.csv'
    # The unclosed quote makes the csv module swallow the following line into
    # one multi-line field; only the empty and junk rows are countable here.
    feed.write_text(
        'ip,tag\n'
        ',missing_indicator\n'
        'not a domain,junk\n'
        '9.9.9.9,known_scanner\n',
        encoding='utf-8')
    table = ThreatIntel()
    loaded = table.load_csv(str(feed))
    assert loaded == 1
    assert table.lookup('9.9.9.9').known_malicious is True


def test_missing_and_oversized_files_are_tolerated(tmp_path):
    table = ThreatIntel()
    assert table.load_csv(str(tmp_path / 'missing.csv')) == 0
    big = tmp_path / 'big.csv'
    big.write_text('9.9.9.9,tag\n' * 1, encoding='utf-8')
    big.write_bytes(b'x' * (5 * 1024 * 1024))
    assert table.load_csv(str(big)) == 0
