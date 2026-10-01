#!/usr/bin/env python3
"""knowledge_admin.py — local developer/admin tooling for the Phase 4
knowledge index.

Subcommands:

- ``index``    ingest/reindex knowledge (idempotent; safe to rerun)
- ``stats``    show index statistics (chunks, documents, per-type counts)
- ``search``   perform a bounded retrieval test against the index

Everything is local and offline: SQLite vector store, deterministic local
embeddings, no network calls, no API keys. Write operations follow the same
local-trust boundary as the rest of the admin tooling (this is a developer
tool, not a network service).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from database import init_db  # noqa: E402
from embeddings import make_indexing_provider, make_embedding_provider  # noqa: E402
from knowledge import KnowledgeIngester  # noqa: E402
from retrieval import KnowledgeRetriever, RetrievalError  # noqa: E402
from vector_store import VectorStore  # noqa: E402

MAX_CLI_RESULTS = 20


def _build_store(args):
    return VectorStore(db_file=args.db)


def _build_ingester(args):
    store = _build_store(args)
    provider = make_indexing_provider()
    return KnowledgeIngester(store, provider, db_file=args.soc_db)


def cmd_index(args):
    ingester = _build_ingester(args)
    if args.soc_db:
        # Ensure the SOC schema exists so historical incidents can be read.
        init_db(args.soc_db)
    summary = ingester.reindex_all(
        include_incidents=not args.no_incidents,
        incident_limit=args.incident_limit)
    print(json.dumps({
        'detection_rules': len(summary['detection_rules']),
        'mitre_techniques': len(summary['mitre_techniques']),
        'threat_intel_documents': len(summary['threat_intel']['documents']),
        'investigation_guides': len(summary['investigation_guides']),
        'project_docs': len(summary['project_docs']),
        'historical_incidents': len(summary.get('historical_incidents', [])),
        'index': summary['stats'],
    }, indent=2, default=str))
    return 0


def cmd_stats(args):
    store = _build_store(args)
    print(json.dumps(store.stats(), indent=2, default=str))
    return 0


def cmd_search(args):
    store = _build_store(args)
    provider = make_embedding_provider()
    if not provider.available():
        # Search needs an embedding; fall back to the offline local provider
        # so CLI retrieval tests work without configuration.
        provider = make_indexing_provider()
    retriever = KnowledgeRetriever(store, provider)
    try:
        results = retriever.retrieve(
            args.query, top_k=args.top_k,
            filters=_parse_filters(args.filters))
    except RetrievalError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(results, indent=2, default=str))
    return 0


def _parse_filters(raw):
    """Parse 'key=value' filter pairs; unknown keys fail closed downstream."""
    if not raw:
        return None
    filters = {}
    for item in raw:
        key, separator, value = item.partition('=')
        if not separator or not key.strip() or not value.strip():
            raise SystemExit(f'invalid filter {item!r}: expected key=value')
        filters[key.strip()] = value.strip()
    return filters


def build_parser():
    parser = argparse.ArgumentParser(
        prog='knowledge_admin',
        description='Index, inspect, and test the ThreatWatch knowledge base.')
    parser.add_argument('--db', default=None,
                        help='vector store SQLite file (default KNOWLEDGE_DB_FILE or knowledge.sqlite)')
    parser.add_argument('--soc-db', default=None,
                        help='SOC database file for historical incidents (default DB_FILE or db.sqlite)')
    sub = parser.add_subparsers(dest='command', required=True)

    index_parser = sub.add_parser('index', help='ingest/reindex all knowledge sources')
    index_parser.add_argument('--no-incidents', action='store_true',
                              help='skip historical incident ingestion')
    index_parser.add_argument('--incident-limit', type=int, default=100,
                              help='maximum historical incidents to index (default 100)')
    index_parser.set_defaults(func=cmd_index)

    stats_parser = sub.add_parser('stats', help='show index statistics')
    stats_parser.set_defaults(func=cmd_stats)

    search_parser = sub.add_parser('search', help='run a retrieval test query')
    search_parser.add_argument('query', help='natural-language query')
    search_parser.add_argument('--top-k', type=int, default=None,
                               help='results to return (bounded by retriever limits)')
    search_parser.add_argument('--filter', dest='filters', action='append',
                               metavar='KEY=VALUE',
                               help='metadata filter, e.g. document_type=detection_rule')
    search_parser.set_defaults(func=cmd_search)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
