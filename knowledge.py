"""Security-knowledge ingestion pipeline (Phase 4C).

Turns ThreatWatch's own security knowledge — detection rules, MITRE ATT&CK
mappings, threat-intelligence entries, investigation guidance, historical
incident summaries, and project documentation — into normalized documents,
deterministic chunks, and vectors in the local vector store.

Safety properties:

- **Explicit sources only.** Nothing is ingested from arbitrary paths; every
  ingested stream comes from the rule registry, the SOC database, the local
  threat-intel CSV, or a fixed allowlist of repository documentation files.
- **Secret-safe.** Every text passes :func:`evidence.redact_text` before it is
  chunked, hashed, or embedded; the intel CSV is parsed structurally so
  credentials never enter documents.
- **Idempotent.** Document IDs and chunk IDs are deterministic; re-ingesting
  unchanged content overwrites the same rows instead of duplicating them.
- **Bounded.** Document and chunk counts/lengths are capped.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import sqlite3
from contextlib import contextmanager

from database import utc_now
from evidence import redact_text
from rules import ATTACK_TECHNIQUE_NAMES, load_rules

logger = logging.getLogger('threatwatch.knowledge')

KNOWLEDGE_SCHEMA_VERSION = 1
CHUNK_MAX_CHARS = 800
CHUNK_OVERLAP_CHARS = 120
MIN_CHUNK_CHARS = 40
MAX_DOCUMENTS_PER_SOURCE = 2000
MAX_CHUNKS_PER_DOCUMENT = 64
MAX_DOCUMENT_CHARS = 200_000
MAX_DOC_FILE_BYTES = 512 * 1024

# Explicit document types (stable metadata contract).
DOCUMENT_TYPE_DETECTION_RULE = 'detection_rule'
DOCUMENT_TYPE_MITRE_TECHNIQUE = 'mitre_technique'
DOCUMENT_TYPE_THREAT_INTELLIGENCE = 'threat_intelligence'
DOCUMENT_TYPE_INVESTIGATION_GUIDE = 'investigation_guide'
DOCUMENT_TYPE_HISTORICAL_INCIDENT = 'historical_incident'
DOCUMENT_TYPE_PROJECT_DOCUMENTATION = 'project_documentation'

DOCUMENT_TYPES = (
    DOCUMENT_TYPE_DETECTION_RULE,
    DOCUMENT_TYPE_MITRE_TECHNIQUE,
    DOCUMENT_TYPE_THREAT_INTELLIGENCE,
    DOCUMENT_TYPE_INVESTIGATION_GUIDE,
    DOCUMENT_TYPE_HISTORICAL_INCIDENT,
    DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
)

SOURCE_RULES = 'detection_rules'
SOURCE_MITRE = 'mitre_mappings'
SOURCE_THREAT_INTEL = 'threat_intel_feed'
SOURCE_GUIDES = 'investigation_guidance'
SOURCE_INCIDENTS = 'historical_alerts'
SOURCE_PROJECT_DOCS = 'project_docs'

# Fixed allowlist of repository documentation (relative to the project root).
# Ingestion never accepts caller-supplied paths.
DOC_ALLOWLIST = ('README.md', 'LICENSE.txt')

_DOCUMENT_ID_FORBIDDEN = re.compile(r'[^a-z0-9._-]+')


class KnowledgeError(ValueError):
    """A knowledge-ingestion request was malformed or unsafe."""


def _slug(text, max_length=96):
    slug = _DOCUMENT_ID_FORBIDDEN.sub('-', str(text).strip().lower())
    slug = slug.strip('-.')
    return (slug[:max_length].rstrip('-.') or 'untitled')


def _stable_document_id(document_type, name):
    return f'{document_type}:{_slug(name)}'


def _chunk_ids(document_id, index):
    return f'{document_id}#{index:03d}'


def _content_fingerprint(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def normalize_text(text):
    """Bound and normalize document text without changing its meaning."""
    if not isinstance(text, str):
        raise KnowledgeError('document text must be a string')
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    text = redact_text(text, MAX_DOCUMENT_CHARS)
    if len(text) > MAX_DOCUMENT_CHARS:
        text = text[:MAX_DOCUMENT_CHARS - 3] + '...'
    return text


def chunk_text(text, max_chars=CHUNK_MAX_CHARS, overlap=CHUNK_OVERLAP_CHARS,
               min_chars=MIN_CHUNK_CHARS):
    """Split text into deterministic, bounded, overlapping chunks.

    Splits prefer paragraph boundaries, then sentence boundaries, then hard
    cuts. Output depends only on the input text and the three numeric
    parameters: same text in, same chunks out.
    """
    if not isinstance(text, str):
        raise KnowledgeError('text must be a string')
    if max_chars < 100 or max_chars > MAX_DOCUMENT_CHARS:
        raise KnowledgeError('max_chars out of bounds')
    if overlap < 0 or overlap >= max_chars:
        raise KnowledgeError('overlap must be smaller than max_chars')
    text = text.strip()
    if not text:
        return []
    paragraphs = [block.strip() for block in text.split('\n\n') if block.strip()]
    units = []
    for paragraph in paragraphs:
        if len(paragraph) <= max_chars:
            units.append(paragraph)
            continue
        # Oversized paragraph: split on sentence enders, then hard-cut.
        sentences = re.split(r'(?<=[.!?])\s+', paragraph)
        current = ''
        for sentence in sentences:
            while len(sentence) > max_chars:
                if current:
                    units.append(current)
                    current = ''
                units.append(sentence[:max_chars])
                sentence = sentence[max_chars - overlap:] if overlap else sentence[max_chars:]
            if not sentence:
                continue
            candidate = f'{current} {sentence}'.strip() if current else sentence
            if len(candidate) <= max_chars:
                current = candidate
            else:
                if current:
                    units.append(current)
                current = sentence
        if current:
            units.append(current)
    # Merge adjacent tiny units so we do not fragment small paragraphs.
    merged = []
    for unit in units:
        if merged and len(merged[-1]) + len(unit) + 1 <= max_chars and (
                len(merged[-1]) < min_chars or len(unit) < min_chars):
            merged[-1] = f'{merged[-1]}\n\n{unit}' if '\n\n' not in unit[:1] else merged[-1] + unit
        else:
            merged.append(unit)
    chunks = []
    for index, unit in enumerate(merged):
        body = unit
        if index > 0 and overlap and len(merged[index - 1]) > 0:
            tail = merged[index - 1][-overlap:]
            # Only carry readable overlap across paragraph-internal splits.
            if not body.startswith(tail) and '\n\n' not in tail:
                body = f'{tail} {body}' if len(body) + overlap <= max_chars else body
        chunks.append(body.strip())
    return chunks[:MAX_CHUNKS_PER_DOCUMENT]


def build_document_chunks(document):
    """Deterministically chunk one normalized document into store items.

    Returns a dict with the document metadata and its bounded chunk list;
    chunk IDs embed the content fingerprint's length is NOT included, so
    unchanged documents produce identical IDs (idempotent re-ingestion).
    """
    required = ('document_id', 'document_type', 'source', 'title', 'content')
    for field in required:
        value = document.get(field)
        if not isinstance(value, str) or not value.strip():
            raise KnowledgeError(f'document field {field!r} is required')
    if document['document_type'] not in DOCUMENT_TYPES:
        raise KnowledgeError(f'unknown document_type: {document["document_type"]}')
    content = normalize_text(document['content'])
    title = redact_text(document['title'], 256)
    fingerprint = _content_fingerprint(content)
    parts = chunk_text(content)
    metadata = dict(document.get('metadata') or {})
    base_metadata = {
        'document_type': document['document_type'],
        'source': document['source'],
        'title': title,
        'content_hash': fingerprint,
        'version': int(document.get('version') or 1),
        'classification': document.get('classification') or 'internal',
        'ingested_at': document.get('updated_at') or utc_now(),
    }
    for key, value in base_metadata.items():
        metadata.setdefault(key, value)
    chunks = []
    for index, part in enumerate(parts):
        chunks.append({
            'chunk_id': _chunk_ids(document['document_id'], index),
            'document_id': document['document_id'],
            'document_type': document['document_type'],
            'source': document['source'],
            'title': title,
            'content': part,
            'content_sha256': fingerprint,
            'metadata': dict(metadata),
        })
    return {
        'document_id': document['document_id'],
        'document_type': document['document_type'],
        'source': document['source'],
        'title': title,
        'content_hash': fingerprint,
        'version': int(document.get('version') or 1),
        'chunk_count': len(chunks),
        'chunks': chunks,
    }


class KnowledgeIngester:
    """Indexes ThreatWatch security knowledge into the vector store."""

    def __init__(self, store, embedding_provider, db_file=None):
        self.store = store
        self.provider = embedding_provider
        self.db_file = db_file

    # -- low-level helpers ----------------------------------------------------

    def _embed_and_index(self, prepared):
        chunks = prepared['chunks']
        if not chunks:
            return 0
        vectors = self.provider.embed_many([chunk['content'] for chunk in chunks])
        if len(vectors) != len(chunks):
            raise KnowledgeError('embedding provider returned an unexpected count')
        model = self.provider.describe().get('model') or 'unknown'
        self.store.set_embedding_model(model)
        items = []
        for chunk, vector in zip(chunks, vectors):
            items.append({
                'chunk_id': chunk['chunk_id'],
                'document_id': chunk['document_id'],
                'document_type': chunk['document_type'],
                'source': chunk['source'],
                'title': chunk['title'],
                'content': chunk['content'],
                'metadata': dict(chunk['metadata'], embedding_model=model),
                'embedding': vector,
            })
        self.store.upsert_many(items)
        return len(items)

    def _index_document(self, document):
        prepared = build_document_chunks(document)
        indexed = self._embed_and_index(prepared)
        self._remove_stale_chunks(
            prepared['document_id'], prepared['chunk_count'])
        return {
            'document_id': prepared['document_id'],
            'chunks': indexed,
            'content_hash': prepared['content_hash'],
        }

    def _remove_stale_chunks(self, document_id, keep_count):
        """Delete chunks left over from a larger previous version."""
        existing = self.store.get_document_chunks(document_id)
        stale = [record['chunk_id'] for record in existing
                 if int(record['chunk_id'].rsplit('#', 1)[-1]) >= keep_count]
        for chunk_id in stale:
            self.store.delete(chunk_id)
        return len(stale)

    # -- source 1: detection rules ---------------------------------------------

    def ingest_detection_rules(self, environ=None):
        """One document per detection rule from the authoritative registry."""
        registry = load_rules(environ)
        results = []
        for rule in registry.all():
            techniques = list(rule.mitre)
            named = [f'{tid} ({ATTACK_TECHNIQUE_NAMES.get(tid, "unknown technique")})'
                     for tid in techniques]
            lines = [
                f'Detection rule {rule.rule_id}: {rule.name}.',
                f'Alert code: {rule.code}. Severity: {rule.severity}.',
                f'Consumes event types: {", ".join(rule.event_types) or "none"}.',
                f'Trigger threshold: {rule.threshold}'
                + (f' within {rule.window_seconds} seconds' if rule.window_seconds else '')
                + f'. Detector confidence: {rule.confidence}.',
                f'What it detects: {rule.description}',
            ]
            if named:
                lines.append('MITRE ATT&CK mappings: ' + '; '.join(named) + '.')
            if rule.tags:
                lines.append('Tags: ' + ', '.join(rule.tags) + '.')
            lines.append(
                'Analyst guidance: confirm the rule threshold against baseline '
                'activity, review the correlated events, and validate whether '
                'the activity was authorized before escalating.')
            document = {
                'document_id': _stable_document_id(
                    DOCUMENT_TYPE_DETECTION_RULE, f'{rule.rule_id}-{rule.name}'),
                'document_type': DOCUMENT_TYPE_DETECTION_RULE,
                'source': SOURCE_RULES,
                'title': f'{rule.rule_id} {rule.name}',
                'content': '\n\n'.join(lines),
                'metadata': {
                    'rule_id': rule.rule_id,
                    'alert_code': rule.code,
                    'severity': rule.severity,
                    'mitre_techniques': techniques,
                },
                'version': 1,
            }
            results.append(self._index_document(document))
        return results

    # -- source 2: MITRE ATT&CK mappings ----------------------------------------

    def ingest_mitre_techniques(self):
        """One document per ATT&CK technique actually mapped by project rules."""
        registry = load_rules()
        by_technique = {}
        for rule in registry.all():
            for technique in rule.mitre:
                by_technique.setdefault(technique, []).append(rule)
        results = []
        for technique in sorted(by_technique):
            rules = by_technique[technique]
            name = ATTACK_TECHNIQUE_NAMES.get(technique)
            if not name:
                continue  # only label mappings the project actually declares
            rule_list = ', '.join(f'{rule.rule_id} ({rule.name})' for rule in rules)
            content = (
                f'MITRE ATT&CK technique {technique}: {name}.\n\n'
                f'ThreatWatch maps this technique in detection rules: {rule_list}.\n\n'
                f'Investigation guidance: when this technique appears on an alert, '
                f'review the rule evidence for {", ".join(rule.rule_id for rule in rules)}, '
                f'correlate related alerts by source indicator, and check adjacent '
                f'telemetry (authentication, process, and network events) around the '
                f'alert time before concluding.')
            document = {
                'document_id': _stable_document_id(
                    DOCUMENT_TYPE_MITRE_TECHNIQUE, f'{technique}-{name}'),
                'document_type': DOCUMENT_TYPE_MITRE_TECHNIQUE,
                'source': SOURCE_MITRE,
                'title': f'{technique} {name}',
                'content': content,
                'metadata': {
                    'mitre_techniques': [technique],
                    # Free-form store metadata is scalar-only; the structured
                    # rule linkage for retrieval filters is rule-level anyway.
                    'rule_ids': ','.join(sorted(rule.rule_id for rule in rules)),
                },
                'version': 1,
            }
            results.append(self._index_document(document))
        return results

    # -- source 3: threat intelligence -------------------------------------------

    def ingest_threat_intel(self, csv_path=None):
        """Structured ingestion of the local threat-intel CSV (never raw text)."""
        from threat_intel import ThreatIntel
        path = csv_path or os.environ.get('THREAT_INTEL') or 'threat_intel.csv'
        intel = ThreatIntel()
        loaded = intel.load_csv(path)
        documents = []
        # Group by source to keep the document count bounded and stable.
        by_source = {}
        for indicator in sorted(intel._table):
            tag, confidence, source = intel._table[indicator]
            by_source.setdefault(source, []).append((indicator, tag, confidence))
        for source in sorted(by_source):
            rows = by_source[source]
            lines = [f'Threat-intelligence entries from source: {source}.']
            for indicator, tag, confidence in rows[:MAX_DOCUMENTS_PER_SOURCE]:
                lines.append(
                    f'Indicator {indicator} is listed as {tag} with confidence '
                    f'{confidence:.2f}.')
            if len(rows) > MAX_DOCUMENTS_PER_SOURCE:
                lines.append(f'... {len(rows) - MAX_DOCUMENTS_PER_SOURCE} more entries omitted.')
            lines.append(
                'Analyst guidance: treat matches as context, not conclusions; '
                'validate indicator activity in adjacent telemetry before acting.')
            slug = _slug(source)
            document = {
                'document_id': _stable_document_id(
                    DOCUMENT_TYPE_THREAT_INTELLIGENCE, f'{slug}-{len(rows)}'),
                'document_type': DOCUMENT_TYPE_THREAT_INTELLIGENCE,
                'source': SOURCE_THREAT_INTEL,
                'title': f'Threat intel: {source} ({len(rows)} indicators)',
                'content': '\n\n'.join(lines),
                'metadata': {'intel_source': source, 'indicator_count': len(rows)},
                'version': 1,
            }
            documents.append(document)
        results = [self._index_document(document) for document in documents]
        return {'loaded': loaded, 'documents': results}

    # -- source 4: investigation guidance -----------------------------------------

    def ingest_investigation_guides(self):
        """Deterministic investigation playbooks derived from project config."""
        from investigation import RULE_INVESTIGATION, TECHNIQUE_INVESTIGATION
        registry = load_rules()
        results = []
        # Per-rule guidance documents.
        for rule in registry.all():
            technique_steps = []
            for technique in rule.mitre:
                step = TECHNIQUE_INVESTIGATION.get(technique)
                if step:
                    technique_steps.append(f'For {technique}: {step}')
            rule_step = RULE_INVESTIGATION.get(rule.rule_id)
            lines = [
                f'Investigation guide for rule {rule.rule_id} ({rule.name}).',
                f'The rule fires on {", ".join(rule.event_types) or "its event types"}; '
                f'severity {rule.severity}.',
            ]
            if rule_step:
                lines.append(f'First step: {rule_step}')
            if technique_steps:
                lines.append('\n'.join(technique_steps))
            lines.append(
                'General steps: open the alert investigation package, review the '
                'timeline and entities, check threat-intelligence matches for the '
                'indicators, correlate related alerts, and record the outcome in '
                'the investigation status with an audit trail.')
            document = {
                'document_id': _stable_document_id(
                    DOCUMENT_TYPE_INVESTIGATION_GUIDE, f'rule-{rule.rule_id}'),
                'document_type': DOCUMENT_TYPE_INVESTIGATION_GUIDE,
                'source': SOURCE_GUIDES,
                'title': f'Guide: investigating {rule.rule_id}',
                'content': '\n\n'.join(lines),
                'metadata': {
                    'rule_id': rule.rule_id,
                    'mitre_techniques': list(rule.mitre),
                },
                'version': 1,
            }
            results.append(self._index_document(document))
        # One lifecycle/how-to guide (uses project terminology).
        lifecycle = (
            'Investigation lifecycle guide.\n\n'
            'Every SOC alert starts with status new. Analysts progress it through '
            'investigating to resolved or dismissed; the transition matrix rejects '
            'invalid moves deterministically and every accepted transition is '
            'written to the investigation_events audit table.\n\n'
            'Use the investigation package (risk, evidence, timeline, indicators, '
            'threat intel, MITRE ATT&CK context, related alerts, analyst questions) '
            'to work the alert. Use the hunting layer for bounded event queries '
            'linked to the alert, correlation ID, or ATT&CK technique.')
        document = {
            'document_id': _stable_document_id(
                DOCUMENT_TYPE_INVESTIGATION_GUIDE, 'lifecycle-and-packages'),
            'document_type': DOCUMENT_TYPE_INVESTIGATION_GUIDE,
            'source': SOURCE_GUIDES,
            'title': 'Guide: investigation lifecycle and packages',
            'content': lifecycle,
            'metadata': {},
            'version': 1,
        }
        results.append(self._index_document(document))
        return results

    # -- source 5: historical incidents ---------------------------------------------

    def ingest_historical_incidents(self, db_file=None, limit=100):
        """Summaries of resolved/dismissed alerts (status only, no free text)."""
        db_file = db_file or self.db_file
        try:
            with _connect_soc(db_file) as connection:
                rows = connection.execute(
                    'SELECT id, time, rule, severity, rule_id, correlation_id, '
                    'deterministic_risk_score, risk_band, investigation_status '
                    'FROM alerts WHERE investigation_status IN (\'resolved\', \'dismissed\') '
                    'ORDER BY id DESC LIMIT ?', (int(limit),)).fetchall()
        except sqlite3.OperationalError as exc:
            # Fresh deployments may not have an initialized SOC database yet;
            # historical ingestion is optional context, never a hard failure.
            logger.warning('Historical incident ingestion skipped (%s)', exc)
            return []
        results = []
        for row in rows:
            # Structural fields only: no details/evidence text is ingested.
            content = (
                f'Historical incident summary for alert {row["id"]}.\n\n'
                f'Rule: {row["rule"]} ({row["rule_id"] or "rule id unavailable"}). '
                f'Severity: {row["severity"]}. Risk score: '
                f'{row["deterministic_risk_score"] if row["deterministic_risk_score"] is not None else "unavailable"} '
                f'(band {row["risk_band"] or "unavailable"}).\n'
                f'Alert time: {row["time"]}. Correlation ID: '
                f'{row["correlation_id"] or "none"}.\n'
                f'Final status: {row["investigation_status"]}.')
            document = {
                'document_id': _stable_document_id(
                    DOCUMENT_TYPE_HISTORICAL_INCIDENT, f'alert-{row["id"]}'),
                'document_type': DOCUMENT_TYPE_HISTORICAL_INCIDENT,
                'source': SOURCE_INCIDENTS,
                'title': f'Incident: alert {row["id"]} ({row["rule"]})',
                'content': content,
                'metadata': {
                    'alert_id': row['id'],
                    'rule_id': row['rule_id'],
                    'correlation_id': row['correlation_id'],
                    'timestamp': row['time'],
                    'outcome': row['investigation_status'],
                },
                'version': 1,
            }
            results.append(self._index_document(document))
        return results

    # -- source 6: project documentation ----------------------------------------------

    def ingest_project_docs(self, root=None):
        """Ingest the fixed documentation allowlist from the project root."""
        root = os.path.abspath(root or os.path.dirname(os.path.abspath(__file__)))
        results = []
        for relative in DOC_ALLOWLIST:
            path = os.path.abspath(os.path.join(root, relative))
            # Defense in depth: the resolved path must stay inside the root.
            if not path.startswith(root + os.sep) and path != root:
                raise KnowledgeError('documentation path escaped the project root')
            if not os.path.isfile(path):
                continue
            if os.path.getsize(path) > MAX_DOC_FILE_BYTES:
                logger.warning('Skipping oversized documentation file: %s', relative)
                continue
            with open(path, 'r', encoding='utf-8', errors='replace') as stream:
                text = stream.read(MAX_DOCUMENT_CHARS)
            document = {
                'document_id': _stable_document_id(
                    DOCUMENT_TYPE_PROJECT_DOCUMENTATION, relative),
                'document_type': DOCUMENT_TYPE_PROJECT_DOCUMENTATION,
                'source': SOURCE_PROJECT_DOCS,
                'title': relative,
                'content': text,
                'metadata': {'file': relative},
                'version': 1,
            }
            results.append(self._index_document(document))
        return results

    # -- orchestration ---------------------------------------------------------------

    def reindex_all(self, include_incidents=True, incident_limit=100):
        """Re-ingest every source idempotently; returns a summary dict."""
        summary = {
            'detection_rules': self.ingest_detection_rules(),
            'mitre_techniques': self.ingest_mitre_techniques(),
            'threat_intel': self.ingest_threat_intel(),
            'investigation_guides': self.ingest_investigation_guides(),
            'project_docs': self.ingest_project_docs(),
        }
        if include_incidents:
            summary['historical_incidents'] = self.ingest_historical_incidents(
                db_file=self.db_file, limit=incident_limit)
        summary['stats'] = self.store.stats()
        return summary


@contextmanager
def _connect_soc(db_file):
    """Local connection helper so knowledge.py does not import app code."""
    connection = sqlite3.connect(db_file or 'db.sqlite', timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()
