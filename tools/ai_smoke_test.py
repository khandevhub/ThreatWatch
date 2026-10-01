#!/usr/bin/env python3
"""ai_smoke_test.py — OPTIONAL manual live-LLM smoke test (Phase 4E-4K).

This script is NOT part of the pytest suite and makes REAL LLM calls. Run it
only when you have explicitly configured an OpenAI-compatible provider:

    # PowerShell
    $env:AI_LLM_PROVIDER = "openai-compatible"
    $env:AI_LLM_API_KEY  = "<your key>"        # or AI_LLM_API_KEY_FILE
    # $env:AI_LLM_ENDPOINT = "https://api.openai.com/v1/chat/completions"
    # $env:AI_LLM_MODEL   = "gpt-4o-mini"

    # bash
    export AI_LLM_PROVIDER=openai-compatible
    export AI_LLM_API_KEY="<your key>"

Then run against your local demo data (it never modifies the SOC database):

    uv run python tools/ai_smoke_test.py             # investigate latest alert
    uv run python tools/ai_smoke_test.py --alert-id 3
    uv run python tools/ai_smoke_test.py --hunt "failed logins from 203.0.113.x"
    uv run python tools/ai_smoke_test.py --check      # config check only, no call

Behavior:

- Refuses to run unless AI_LLM_PROVIDER is explicitly configured.
- Never prints or stores the API key.
- Prints a redacted, structured view of the AI result (or the failure reason).
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai_hunting import execute_ai_hunt  # noqa: E402
from ai_investigation import AIInvestigationEngine  # noqa: E402
from database import DB as DEFAULT_DB, init_db  # noqa: E402
from llm_provider import make_llm_provider  # noqa: E402


def _latest_alert_id(db_file):
    with sqlite3.connect(db_file) as connection:
        row = connection.execute(
            'SELECT id FROM alerts ORDER BY id DESC LIMIT 1').fetchone()
    return row[0] if row else None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='OPTIONAL live-LLM smoke test (makes real API calls).')
    parser.add_argument('--db', default=None, help='SOC database file')
    parser.add_argument('--knowledge-db', default=None,
                        help='knowledge vector store file')
    parser.add_argument('--alert-id', type=int, default=None,
                        help='alert to investigate (default: latest)')
    parser.add_argument('--hunt', default=None,
                        help='run an AI-assisted hunt with this natural-language query')
    parser.add_argument('--check', action='store_true',
                        help='verify configuration only; make no LLM call')
    args = parser.parse_args(argv)

    if (os.environ.get('AI_LLM_PROVIDER') or 'disabled').strip().lower() \
            in ('', 'disabled', 'none', 'off'):
        print('Refusing to run: AI_LLM_PROVIDER is not configured.\n'
              'Set AI_LLM_PROVIDER=openai-compatible and AI_LLM_API_KEY '
              '(see module docstring). The pytest suite never needs this.')
        return 2

    try:
        provider = make_llm_provider()
    except Exception as exc:
        print(f'Provider configuration error: {type(exc).__name__}')
        return 2
    if not provider.available():
        print('Provider is not available (missing API key?).')
        return 2
    print('Provider:', json.dumps(provider.describe()))

    db_file = args.db or DEFAULT_DB
    init_db(db_file)
    engine = AIInvestigationEngine(db_file=db_file,
                                   knowledge_db_file=args.knowledge_db)

    if args.check:
        print('Configuration OK; no LLM call made (--check).')
        return 0

    if args.hunt:
        outcome = execute_ai_hunt(args.hunt, db_file=db_file)
        query = outcome['query']
        print('\n== AI hunt ==')
        print('Explanation:', query.get('explanation') or '(none)')
        print('Validated filters:', json.dumps(query['filters']))
        print('Results total:', outcome['results'].get('total'))
        rows = outcome['results'].get('results', [])[:5]
        for row in rows:
            print(' -', row.get('event_time'), row.get('event_type'),
                  row.get('src_ip'), row.get('user'))
        print('AI summary:', json.dumps(outcome['summary'], indent=2)[:2000])
        return 0

    alert_id = args.alert_id if args.alert_id is not None \
        else _latest_alert_id(db_file)
    if alert_id is None:
        print('No alerts found in', db_file,
              '- run the demo/collector first.')
        return 1
    print(f'Investigating alert {alert_id} with a REAL LLM call...')
    result = engine.investigate(alert_id)
    if result.get('status') != 'ok':
        print('AI investigation unavailable:',
              json.dumps({k: v for k, v in result.items() if k != 'response'}))
        return 1
    response = result['response']
    print('\n== AI investigation (ADVISORY) ==')
    print('Model:', json.dumps(result['model']))
    print('Priority:', response['priority'],
          '| malicious:', response['malicious_likelihood'],
          '| false-positive:', response['false_positive_likelihood'],
          '| confidence:', response['confidence'])
    print('\nSummary:', response['summary'])
    print('\nAssessment:', response['assessment'])
    print('\nKey evidence:')
    for item in response['key_evidence']:
        print(' -', item)
    print('\nGrounding:', json.dumps(result['grounding']),
          '| source references:', json.dumps(response['source_references']))
    print('\nRecommended actions:')
    for action in response['recommended_actions']:
        print(' -', action['action'], '|', action['reason'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
