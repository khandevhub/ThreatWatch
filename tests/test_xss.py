"""Dashboard alert fields are rendered as text, not executable markup."""
from pathlib import Path


def test_alert_rendering_uses_text_nodes_and_fixed_severity_classes():
    script = Path(__file__).parents[1] / 'static' / 'dashboard.js'
    source = script.read_text(encoding='utf-8')

    assert 'innerHTML' not in source
    assert 'details.textContent = alert.details' in source
    assert "severityClasses[alert.severity] || 'unknown'" in source
    assert "card.className = 'alert '" in source
