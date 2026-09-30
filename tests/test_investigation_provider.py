"""Phase 3G: investigation provider interface, offline providers, wiring."""
import pytest

from investigation_provider import (
    AI_PERSPECTIVE_KEY, DisabledInvestigationProvider,
    InvestigationProvider, MockInvestigationProvider,
    apply_investigation_provider, make_investigation_provider)


@pytest.fixture()
def package():
    """Minimal investigation-package shape the providers consume."""
    return {
        'alert': {'rule': 'PASSWORD_SPRAYING', 'severity': 'HIGH'},
        'risk': {'score': 47, 'band': 'high'},
        'evidence': {
            'event_count': 5,
            'entities': {
                'source_ips': ['203.0.113.7'],
                'usernames': ['alice', 'bob'],
                'hostnames': [],
                'processes': [],
            },
        },
        'mitre': {'techniques': [
            {'technique_id': 'T1110.003', 'technique_name': 'Password Spraying'},
        ]},
    }


# -- interface contract -------------------------------------------------------

def test_base_provider_is_abstract_and_offline():
    provider = InvestigationProvider()
    assert provider.available() is False
    with pytest.raises(NotImplementedError):
        provider.investigate({})
    with pytest.raises(NotImplementedError):
        provider.summarize({})
    with pytest.raises(NotImplementedError):
        provider.generate_hypotheses({})


# -- mock provider ------------------------------------------------------------

def test_mock_provider_summary_is_deterministic(package):
    provider = MockInvestigationProvider()
    first = provider.summarize(package)
    second = provider.summarize(package)
    assert first == second
    assert 'PASSWORD_SPRAYING' in first
    assert '47/100' in first
    assert '203.0.113.7' in first


def test_mock_provider_hypotheses_are_grounded_and_deterministic(package):
    provider = MockInvestigationProvider()
    first = provider.generate_hypotheses(package)
    second = provider.generate_hypotheses(package)
    assert first == second
    assert any('203.0.113.7' in hypothesis for hypothesis in first)
    assert any('alice' in hypothesis for hypothesis in first)
    assert any('T1110.003' in hypothesis for hypothesis in first)
    assert all(len(hypothesis) < 300 for hypothesis in first)


def test_mock_provider_handles_empty_package():
    provider = MockInvestigationProvider()
    hypotheses = provider.generate_hypotheses({})
    assert hypotheses == ['Insufficient entity evidence; correlate with '
                          'adjacent telemetry for the affected host.']
    summary = provider.summarize({})
    assert 'Unknown rule' in summary


def test_mock_provider_investigate_is_advisory_only(package):
    provider = MockInvestigationProvider()
    analysis = provider.investigate(package)
    assert analysis['provider'] == 'mock'
    assert analysis['advisory_only'] is True
    assert analysis['summary'] == provider.summarize(package)
    assert analysis['hypotheses'] == provider.generate_hypotheses(package)


# -- disabled provider ----------------------------------------------------------

def test_disabled_provider_returns_nothing():
    provider = DisabledInvestigationProvider()
    assert provider.available() is False
    assert provider.investigate({}) is None
    assert provider.summarize({}) is None
    assert provider.generate_hypotheses({}) == []


# -- provider selection ----------------------------------------------------------

@pytest.mark.parametrize('enabled_value', ('1', 'true', 'YES', 'On'))
def test_enabled_env_selects_mock_provider(enabled_value):
    provider = make_investigation_provider({'INVESTIGATION_AI_ENABLED': enabled_value})
    assert isinstance(provider, MockInvestigationProvider)
    assert provider.available() is True


@pytest.mark.parametrize('disabled_value', (None, '', '0', 'false', 'off', 'garbage'))
def test_disabled_or_unknown_env_selects_disabled_provider(disabled_value):
    environ = {} if disabled_value is None else {
        'INVESTIGATION_AI_ENABLED': disabled_value}
    provider = make_investigation_provider(environ)
    assert isinstance(provider, DisabledInvestigationProvider)


# -- apply_investigation_provider --------------------------------------------------

def test_apply_disabled_provider_marks_status(package):
    result = apply_investigation_provider(package, DisabledInvestigationProvider())
    assert result is package
    assert result[AI_PERSPECTIVE_KEY]['status'] == 'disabled'
    assert result[AI_PERSPECTIVE_KEY]['provider'] == 'disabled'


def test_apply_mock_provider_attaches_analysis(package):
    result = apply_investigation_provider(package, MockInvestigationProvider())
    perspective = result[AI_PERSPECTIVE_KEY]
    assert perspective['status'] == 'ok'
    assert perspective['provider'] == 'mock'
    assert perspective['advisory_only'] is True
    assert perspective['summary']
    assert perspective['hypotheses']


def test_apply_none_provider_is_treated_as_disabled(package):
    result = apply_investigation_provider(package, None)
    assert result[AI_PERSPECTIVE_KEY]['status'] == 'disabled'


def test_apply_provider_failure_degrades_gracefully(package):
    class BrokenProvider(InvestigationProvider):
        name = 'broken'

        def available(self):
            return True

        def investigate(self, pkg):
            raise RuntimeError('simulated provider crash')

    before = {key: value for key, value in package.items()}
    result = apply_investigation_provider(package, BrokenProvider())
    assert result is package
    perspective = result[AI_PERSPECTIVE_KEY]
    assert perspective['status'] == 'unavailable'
    assert perspective['reason'] == 'provider_error'
    # The original package content is untouched apart from the one new key.
    for key, value in before.items():
        assert result[key] == value


def test_apply_provider_returning_none_marks_unavailable(package):
    class NoOpProvider(InvestigationProvider):
        name = 'noop'

        def available(self):
            return True

        def investigate(self, pkg):
            return None

    result = apply_investigation_provider(package, NoOpProvider())
    assert result[AI_PERSPECTIVE_KEY]['status'] == 'unavailable'
    assert result[AI_PERSPECTIVE_KEY]['provider'] == 'noop'


def test_apply_adds_only_one_key(package):
    keys_before = set(package)
    apply_investigation_provider(package, MockInvestigationProvider())
    assert set(package) - keys_before == {AI_PERSPECTIVE_KEY}
