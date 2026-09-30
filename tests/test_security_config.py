"""Secret-source validation and simulator transport policy tests."""
import pytest

from security_config import SecretConfigurationError, load_ingest_token
from simulator.append_events import _is_loopback_url


TOKEN = 'secure-test-token-' + 'x' * 48


def test_token_can_be_loaded_from_a_secret_file(tmp_path):
    secret_file = tmp_path / 'ingest-token'
    secret_file.write_text(TOKEN + '\n', encoding='utf-8')
    assert load_ingest_token({'INGEST_TOKEN_FILE': str(secret_file)}) == TOKEN


def test_conflicting_or_weak_token_sources_are_rejected(tmp_path):
    secret_file = tmp_path / 'ingest-token'
    secret_file.write_text(TOKEN, encoding='utf-8')
    with pytest.raises(SecretConfigurationError, match='only one'):
        load_ingest_token({'INGEST_TOKEN': TOKEN, 'INGEST_TOKEN_FILE': str(secret_file)})
    with pytest.raises(SecretConfigurationError, match='32 to 4096'):
        load_ingest_token({'INGEST_TOKEN': 'short'})


def test_simulator_allows_only_https_or_loopback_http_for_tokens():
    assert _is_loopback_url('http://127.0.0.1:5000/api/ingest')
    assert _is_loopback_url('http://localhost/api/ingest')
    assert not _is_loopback_url('http://example.com/api/ingest')
    assert _is_loopback_url('https://example.com/api/ingest')
