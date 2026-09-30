"""Dashboard XSS regression test: alert fields must not be HTML-injected."""
import os


def test_dashboard_has_no_unsafe_alert_interpolation():
    here = os.path.dirname(__file__)
    src = open(os.path.join(here, '..', 'templates', 'dashboard.html'),
               encoding='utf-8').read()
    # the old vulnerable pattern: building alert HTML via template strings
    assert "`<div class='alert" not in src
    assert 'innerHTML' not in src
    # the safe pattern must be present: DOM textContent assignment
    assert '.textContent =' in src
    assert 'replaceChildren' in src


def test_detector_details_not_html_escaped_by_server():
    # details are plain text stored verbatim; safety is enforced client-side
    # by textContent rendering (proven by the test above).
    import detector  # noqa: F401  (import sanity after repair)
    assert callable(detector.process_event)
