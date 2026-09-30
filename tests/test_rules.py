"""SOC rule registry: metadata, env overrides, and enable/disable."""
import pytest

from rules import Rule, load_rules


def test_seed_registry_has_ten_rules_with_stable_ids():
    registry = load_rules({})
    assert len(registry) == 10
    ids = [rule.rule_id for rule in registry.all()]
    assert ids == [f'TW-{number:03d}' for number in range(1, 11)]


def test_phase1_threshold_env_names_still_configure_brute_force():
    registry = load_rules({'BRUTE_FORCE_THRESHOLD': '3', 'DETECTION_WINDOW': '30'})
    brute = registry.get('TW-001')
    assert brute.threshold == 3 and brute.window_seconds == 30
    assert brute.code == 'BRUTE_FORCE'  # legacy alert name preserved


def test_rule_environment_overrides():
    registry = load_rules({
        'RULE_TW_002_ENABLED': 'false',
        'RULE_TW_005_SEVERITY': 'LOW',
        'RULE_TW_004_THRESHOLD': '2',
        'RULE_TW_004_WINDOW': '120',
    })
    assert registry.get('TW-002').enabled is False
    assert registry.get('TW-002') not in registry.enabled_rules()
    assert registry.get('TW-005').severity == 'LOW'
    spray = registry.get('TW-004')
    assert spray.threshold == 2 and spray.window_seconds == 120


def test_invalid_override_values_fail_closed():
    with pytest.raises(ValueError):
        load_rules({'RULE_TW_001_THRESHOLD': '0'})
    with pytest.raises(ValueError):
        load_rules({'RULE_TW_001_WINDOW': 'abc'})
    with pytest.raises(ValueError):
        load_rules({'RULE_TW_005_SEVERITY': 'CRITICAL'})
    with pytest.raises(ValueError):
        load_rules({'BRUTE_FORCE_THRESHOLD': 'zero'})


def test_every_rule_declares_mitre_or_explains_why_not():
    for rule in load_rules({}).all():
        if rule.rule_id == 'TW-003':      # traffic spike: no ATT&CK technique yet
            assert rule.mitre == ()
        else:
            assert rule.mitre, f'{rule.rule_id} lacks ATT&CK mapping'


def test_registry_rejects_duplicate_ids():
    registry = load_rules({})
    with pytest.raises(ValueError):
        registry.register(Rule(rule_id='TW-001', name='dup', event_types=('x',)))


def test_rule_with_overrides_returns_new_instance():
    rule = load_rules({}).get('TW-006')
    changed = rule.with_overrides(severity='HIGH')
    assert changed is not rule and changed.severity == 'HIGH'
    assert rule.severity == 'MEDIUM'
