"""Phase 4E-4K dashboard tests: advisory AI section is safe and labeled."""
from pathlib import Path


DASHBOARD = Path(__file__).parents[1] / 'static' / 'dashboard.js'
STYLES = Path(__file__).parents[1] / 'static' / 'style.css'


def _source():
    return DASHBOARD.read_text(encoding='utf-8')


def test_ai_section_uses_text_nodes_only():
    source = _source()
    # The whole file stays innerHTML-free (model output is untrusted).
    assert 'innerHTML' not in source
    assert 'insertAdjacentHTML' not in source
    assert 'document.write' not in source
    # AI values flow exclusively through textContent rendering helpers.
    assert 'function addLines' in source
    assert "item.textContent = line" in source


def test_ai_section_is_clearly_labeled_advisory():
    source = _source()
    assert 'AI-GENERATED / ADVISORY' in source
    assert 'advisory only, can be wrong' in source
    # Jev is shown as deterministic context, distinct from AI output.
    assert 'Jev decision (deterministic, not AI)' in source


def test_ai_section_handles_disabled_and_failed_states():
    source = _source()
    # Disabled/unavailable states render a status line instead of data.
    assert "ai.status !== 'ok'" in source
    assert 'AI status: unavailable' in source


def test_ai_advisory_style_is_visually_distinct():
    styles = STYLES.read_text(encoding='utf-8')
    assert '.ai-advisory' in styles


def test_dashboard_js_still_parses():
    import subprocess
    result = subprocess.run(
        ['node', '--check', str(DASHBOARD)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
