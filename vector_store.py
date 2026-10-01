"""Local vector store (Phase 4A).

A provider-neutral, persistent vector store on top of the SQLite library the
project already uses — no new dependency, no Docker, no cloud service, no API
key. Vectors are stored as JSON float arrays; search computes cosine
similarity in-process, which is fast for the bounded local knowledge indexes
this project targets (hundreds to low thousands of chunks).

Storage lives in its own SQLite file (default ``knowledge.sqlite``) so the
SOC database schema versioning in ``database.py`` is never touched. The store
persists between application restarts.

Metadata is filterable through whitelisted, validated filters only
(document_type, source, technique, rule_id, alert_id, time range); unknown
filters fail closed. Ordering is deterministic: score DESC, then chunk_id.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import sqlite3
from contextlib import contextmanager

from database import utc_now
from hunting import HuntError, _validate_time

logger = logging.getLogger('threatwatch.vector_store')

KNOWLEDGE_DB_ENV = 'KNOWLEDGE_DB_FILE'
KNOWLEDGE_DB_DEFAULT = 'knowledge.sqlite'

SCHEMA_VERSION = 1
MAX_SEARCH_LIMIT = 50
DEFAULT_SEARCH_LIMIT = 10
MAX_CONTENT_CHARS = 32768
MAX_METADATA_KEYS = 32
MAX_METADATA_VALUE_CHARS = 512
MAX_CHUNK_ID_CHARS = 256
MAX_DOCUMENT_ID_CHARS = 256

DOCUMENT_TYPE_PATTERN = re.compile(r'^[a-z][a-z0-9_]{1,63}$')
SOURCE_PATTERN = re.compile(r'^[\w.:/@ -]{1,256}$')
RULE_ID_PATTERN = re.compile(r'^[\w-]{1,32}$')
TECHNIQUE_PATTERN = re.compile(r'^T\d{4}(?:\.\d{3})?$')
META_KEY_PATTERN = re.compile(r'^[\w.-]{1,64}$')

# Metadata keys that are also first-class filterable columns.
STRUCTURED_METADATA_KEYS = (
    'document_type', 'source', 'title', 'mitre_techniques', 'rule_id',
    'alert_id', 'timestamp',
)


class VectorStoreError(ValueError):
    """A vector-store request was malformed or violated store invariants."""


_SCHEMA = '''
CREATE TABLE IF NOT EXISTS knowledge_store_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
'''
_CHUNKS_SCHEMA = '''
CREATE TABLE IF NOT EXISTS knowledge_chunks (
    chunk_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    document_type TEXT NOT NULL,
    source TEXT NOT NULL,
    title TEXT,
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    embedding_json TEXT NOT NULL,
    embedding_model TEXT NOT NULL,
    dimensions INTEGER NOT NULL,
    mitre_techniques_json TEXT,
    rule_id TEXT,
    alert_id INTEGER,
    timestamp TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
'''


@contextmanager
def _connect(db_file):
    connection = sqlite3.connect(db_file, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA busy_timeout = 10000')
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _ensure_schema(connection):
    connection.execute(_SCHEMA)
    connection.execute(_CHUNKS_SCHEMA)
    connection.execute(
        'CREATE INDEX IF NOT EXISTS idx_kchunks_document '
        'ON knowledge_chunks(document_id)')
    connection.execute(
        'CREATE INDEX IF NOT EXISTS idx_kchunks_type ON knowledge_chunks(document_type)')
    connection.execute(
        'CREATE INDEX IF NOT EXISTS idx_kchunks_source ON knowledge_chunks(source)')
    connection.execute(
        'CREATE INDEX IF NOT EXISTS idx_kchunks_rule ON knowledge_chunks(rule_id)')


def _validate_identifier(name, raw, pattern):
    text = str(raw or '').strip()
    if not pattern.match(text):
        raise VectorStoreError(f'{name} is not a valid identifier')
    return text


def _validate_filters(filters):
    """Whitelist and validate metadata filters (fail closed, like hunting)."""
    if filters is None:
        return {}
    if not isinstance(filters, dict):
        raise VectorStoreError('filters must be a mapping')
    validated = {}
    for key in sorted(filters):
        raw = filters[key]
        if raw is None or raw == '':
            continue
        if key == 'document_type':
            validated[key] = _validate_identifier(key, raw, DOCUMENT_TYPE_PATTERN)
        elif key == 'source':
            validated[key] = _validate_identifier(key, raw, SOURCE_PATTERN)
        elif key == 'technique':
            text = str(raw).strip().upper()
            if not TECHNIQUE_PATTERN.match(text):
                raise VectorStoreError('technique must look like T1110 or T1059.001')
            validated[key] = text
        elif key == 'rule_id':
            validated[key] = _validate_identifier(key, raw, RULE_ID_PATTERN)
        elif key == 'alert_id':
            try:
                value = int(raw)
            except (TypeError, ValueError):
                raise VectorStoreError('alert_id must be an integer') from None
            if value < 0:
                raise VectorStoreError('alert_id must be non-negative')
            validated[key] = value
        elif key in ('time_from', 'time_to'):
            try:
                validated[key] = _validate_time(key, str(raw))
            except HuntError as exc:
                raise VectorStoreError(str(exc)) from None
        else:
            raise VectorStoreError(f'unknown filter: {key}')
    return validated


def _where_for(validated):
    clauses, params = [], []
    if 'document_type' in validated:
        clauses.append('document_type = ?')
        params.append(validated['document_type'])
    if 'source' in validated:
        clauses.append('source = ?')
        params.append(validated['source'])
    if 'technique' in validated:
        # Quote-delimited so T1110 never matches T1110.003 (same as hunting).
        clauses.append("mitre_techniques_json LIKE ? ESCAPE '\\'")
        params.append('%"' + validated['technique'] + '"%')
    if 'rule_id' in validated:
        clauses.append('rule_id = ?')
        params.append(validated['rule_id'])
    if 'alert_id' in validated:
        clauses.append('alert_id = ?')
        params.append(validated['alert_id'])
    if 'time_from' in validated:
        clauses.append('timestamp >= ?')
        params.append(validated['time_from'])
    if 'time_to' in validated:
        clauses.append('timestamp <= ?')
        params.append(validated['time_to'])
    return clauses, params


def _validate_metadata(metadata):
    """Coerce metadata into a bounded, flat, JSON-safe dict."""
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise VectorStoreError('metadata must be a mapping')
    if len(metadata) > MAX_METADATA_KEYS:
        raise VectorStoreError(
            f'metadata exceeds {MAX_METADATA_KEYS} keys')
    cleaned = {}
    for key in sorted(metadata, key=str):
        key_text = str(key)
        if not META_KEY_PATTERN.match(key_text):
            raise VectorStoreError(f'invalid metadata key: {key_text!r}')
        value = metadata[key]
        if value is None or isinstance(value, bool):
            cleaned[key_text] = value
        elif isinstance(value, (str, int, float)):
            text = str(value)
            if len(text) > MAX_METADATA_VALUE_CHARS:
                text = text[:MAX_METADATA_VALUE_CHARS - 3] + '...'
            cleaned[key_text] = text if not isinstance(value, (int, float)) else value
        else:
            raise VectorStoreError(
                f'metadata value for {key_text!r} must be a scalar')
    return cleaned


class VectorStore:
    """Persistent SQLite-backed vector store with cosine search."""

    def __init__(self, db_file=None):
        self.db_file = db_file or os.environ.get(KNOWLEDGE_DB_ENV)
        if not self.db_file:
            self.db_file = KNOWLEDGE_DB_DEFAULT
        with _connect(self.db_file) as connection:
            _ensure_schema(connection)

    # -- internals -----------------------------------------------------------

    def _meta(self, connection, key):
        row = connection.execute(
            'SELECT value FROM knowledge_store_meta WHERE key = ?', (key,)).fetchone()
        return row['value'] if row else None

    def _set_meta(self, connection, key, value):
        connection.execute(
            'INSERT INTO knowledge_store_meta (key, value) VALUES (?, ?) '
            'ON CONFLICT(key) DO UPDATE SET value = excluded.value',
            (key, str(value)))

    def _validate_dimensions(self, connection, embedding):
        """Validate embedding shape and the store's dimension invariant."""
        if not isinstance(embedding, (list, tuple)) or not embedding:
            raise VectorStoreError('embedding must be a non-empty list of floats')
        try:
            vector = [float(component) for component in embedding]
        except (TypeError, ValueError):
            raise VectorStoreError('embedding must contain only numbers') from None
        if any(math.isnan(component) or math.isinf(component) for component in vector):
            raise VectorStoreError('embedding must contain finite numbers')
        dimensions = len(vector)
        locked = self._meta(connection, 'dimensions')
        if locked is None:
            self._set_meta(connection, 'dimensions', dimensions)
        elif int(locked) != dimensions:
            raise VectorStoreError(
                f'embedding has {dimensions} dimensions; store uses {locked}')
        return vector

    @staticmethod
    def _row_to_record(row, score=None):
        try:
            embedding = json.loads(row['embedding_json'])
        except (TypeError, ValueError):
            embedding = None
        try:
            techniques = json.loads(row['mitre_techniques_json'] or 'null')
        except (TypeError, ValueError):
            techniques = None
        try:
            metadata = json.loads(row['metadata_json'])
        except (TypeError, ValueError):
            metadata = {}
        record = {
            'chunk_id': row['chunk_id'],
            'document_id': row['document_id'],
            'document_type': row['document_type'],
            'source': row['source'],
            'title': row['title'],
            'content': row['content'],
            'content_sha256': row['content_sha256'],
            'score': score,
            'embedding_model': row['embedding_model'],
            'dimensions': row['dimensions'],
            'mitre_techniques': techniques if isinstance(techniques, list) else [],
            'rule_id': row['rule_id'],
            'alert_id': row['alert_id'],
            'timestamp': row['timestamp'],
            'metadata': metadata if isinstance(metadata, dict) else {},
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }
        if score is None:
            record.pop('score')
        return record

    # -- write API -----------------------------------------------------------

    def upsert(self, chunk_id, embedding, document_id, content,
               document_type, source, metadata=None, title=None,
               embedding_model=None):
        """Insert or update one chunk; validates all inputs fail-closed.

        When ``embedding_model`` is provided it must match the model already
        recorded for this store (or be recorded as the store's model on the
        first write), so vectors from incompatible models can never be mixed
        silently — even when their dimensions happen to be equal.
        """
        if not isinstance(chunk_id, str) or not chunk_id.strip():
            raise VectorStoreError('chunk_id must be a non-empty string')
        if len(chunk_id) > MAX_CHUNK_ID_CHARS:
            raise VectorStoreError('chunk_id exceeds maximum length')
        if not isinstance(document_id, str) or not document_id.strip():
            raise VectorStoreError('document_id must be a non-empty string')
        if len(document_id) > MAX_DOCUMENT_ID_CHARS:
            raise VectorStoreError('document_id exceeds maximum length')
        if not isinstance(content, str) or not content.strip():
            raise VectorStoreError('content must be a non-empty string')
        if len(content) > MAX_CONTENT_CHARS:
            raise VectorStoreError('content exceeds maximum chunk size')
        document_type = _validate_identifier(
            'document_type', document_type, DOCUMENT_TYPE_PATTERN)
        source_name = _validate_identifier('source', source, SOURCE_PATTERN)
        # Structured, filterable metadata keys are extracted first; they have
        # their own validation and must not flow into the free-form metadata.
        if metadata is not None and not isinstance(metadata, dict):
            raise VectorStoreError('metadata must be a mapping')
        working = dict(metadata or {})
        techniques = working.pop('mitre_techniques', None)
        if techniques is None:
            techniques = []
        if not isinstance(techniques, list) or not all(
                isinstance(item, str) and TECHNIQUE_PATTERN.match(item)
                for item in techniques):
            raise VectorStoreError('mitre_techniques must be a list of technique IDs')
        rule_id = working.pop('rule_id', None)
        if rule_id is not None:
            rule_id = _validate_identifier('rule_id', rule_id, RULE_ID_PATTERN)
        alert_id = working.pop('alert_id', None)
        if alert_id is not None:
            try:
                alert_id = int(alert_id)
            except (TypeError, ValueError):
                raise VectorStoreError('alert_id must be an integer') from None
        timestamp = working.pop('timestamp', None)
        title = working.pop('title', None) if title is None else title
        if title is not None:
            if not isinstance(title, str):
                raise VectorStoreError('title must be a string')
            title = title[:256]
        cleaned = _validate_metadata(working)
        now = utc_now()
        with _connect(self.db_file) as connection:
            _ensure_schema(connection)
            vector = self._validate_dimensions(connection, embedding)
            model = self._meta(connection, 'embedding_model')
            if embedding_model is not None:
                if not isinstance(embedding_model, str) or not embedding_model.strip():
                    raise VectorStoreError('embedding_model must be a short string')
                embedding_model = embedding_model.strip()[:128]
                if model is None:
                    self._set_meta(connection, 'embedding_model', embedding_model)
                    model = embedding_model
                elif model != embedding_model:
                    raise VectorStoreError(
                        f'embedding model mismatch: store was indexed with '
                        f'{model!r}; refusing vectors from {embedding_model!r} '
                        f'(reindex or use a new store)')
            model = model or 'unknown'
            existing = connection.execute(
                'SELECT created_at FROM knowledge_chunks WHERE chunk_id = ?',
                (chunk_id,)).fetchone()
            created = existing['created_at'] if existing else now
            connection.execute('''
                INSERT INTO knowledge_chunks (
                    chunk_id, document_id, document_type, source, title, content,
                    content_sha256, embedding_json, embedding_model, dimensions,
                    mitre_techniques_json, rule_id, alert_id, timestamp,
                    metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chunk_id) DO UPDATE SET
                    document_id = excluded.document_id,
                    document_type = excluded.document_type,
                    source = excluded.source,
                    title = excluded.title,
                    content = excluded.content,
                    content_sha256 = excluded.content_sha256,
                    embedding_json = excluded.embedding_json,
                    embedding_model = excluded.embedding_model,
                    dimensions = excluded.dimensions,
                    mitre_techniques_json = excluded.mitre_techniques_json,
                    rule_id = excluded.rule_id,
                    alert_id = excluded.alert_id,
                    timestamp = excluded.timestamp,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
            ''', (
                chunk_id, document_id, document_type, source_name, title, content,
                # content_sha256 is filled by callers that hash; empty here is
                # valid for direct store use.
                _content_hash(content),
                json.dumps(vector, separators=(',', ':')), model, len(vector),
                json.dumps(techniques) if techniques else None,
                rule_id, alert_id, timestamp,
                json.dumps(cleaned, sort_keys=True, separators=(',', ':')),
                created, now,
            ))
        return {
            'chunk_id': chunk_id, 'document_id': document_id,
            'document_type': document_type, 'dimensions': len(vector),
        }

    def upsert_many(self, items):
        """Upsert a bounded batch of chunk dicts (same validation as upsert)."""
        if not isinstance(items, (list, tuple)):
            raise VectorStoreError('items must be a list')
        results = []
        for item in items:
            results.append(self.upsert(
                item.get('chunk_id'), item.get('embedding'),
                item.get('document_id'), item.get('content'),
                item.get('document_type'), item.get('source'),
                metadata=item.get('metadata'), title=item.get('title'),
                embedding_model=item.get('embedding_model')))
        return results

    def delete(self, chunk_id):
        """Delete one chunk; returns True when a row was removed."""
        with _connect(self.db_file) as connection:
            cursor = connection.execute(
                'DELETE FROM knowledge_chunks WHERE chunk_id = ?', (chunk_id,))
            return cursor.rowcount > 0

    def delete_document(self, document_id):
        """Delete every chunk of a document; returns the number removed."""
        with _connect(self.db_file) as connection:
            cursor = connection.execute(
                'DELETE FROM knowledge_chunks WHERE document_id = ?', (document_id,))
            return cursor.rowcount

    # -- read API ------------------------------------------------------------

    def get(self, chunk_id):
        """Return one chunk record (without its vector) or None."""
        with _connect(self.db_file) as connection:
            row = connection.execute(
                'SELECT * FROM knowledge_chunks WHERE chunk_id = ?',
                (chunk_id,)).fetchone()
            return self._row_to_record(row) if row else None

    def get_document_chunks(self, document_id):
        """All chunks of a document, ordered by chunk_id (deterministic)."""
        with _connect(self.db_file) as connection:
            rows = connection.execute(
                'SELECT * FROM knowledge_chunks WHERE document_id = ? '
                'ORDER BY chunk_id', (document_id,)).fetchall()
            return [self._row_to_record(row) for row in rows]

    def search(self, embedding, limit=DEFAULT_SEARCH_LIMIT, offset=0,
               filters=None):
        """Cosine search with validated filters and deterministic ordering."""
        try:
            limit_i = int(limit)
            offset_i = int(offset)
        except (TypeError, ValueError):
            raise VectorStoreError('limit and offset must be integers') from None
        if limit_i < 1 or limit_i > MAX_SEARCH_LIMIT:
            raise VectorStoreError(
                f'limit must be between 1 and {MAX_SEARCH_LIMIT}')
        if offset_i < 0:
            raise VectorStoreError('offset must be non-negative')
        if not isinstance(embedding, (list, tuple)) or not embedding:
            raise VectorStoreError('embedding must be a non-empty list of floats')
        try:
            query = [float(component) for component in embedding]
        except (TypeError, ValueError):
            raise VectorStoreError('embedding must contain only numbers') from None
        validated = _validate_filters(filters)
        clauses, params = _where_for(validated)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        with _connect(self.db_file) as connection:
            _ensure_schema(connection)
            locked = self._meta(connection, 'dimensions')
            if locked is not None and int(locked) != len(query):
                raise VectorStoreError(
                    f'query embedding has {len(query)} dimensions; '
                    f'store uses {locked}')
            rows = connection.execute(
                f'SELECT * FROM knowledge_chunks{where}', tuple(params)).fetchall()
        scored = []
        for row in rows:
            try:
                vector = json.loads(row['embedding_json'])
            except (TypeError, ValueError):
                logger.warning('Skipping chunk with unreadable embedding: %s',
                               row['chunk_id'])
                continue
            if len(vector) != len(query):
                logger.warning('Skipping chunk with mismatched dimensions: %s',
                               row['chunk_id'])
                continue
            scored.append((_cosine(query, vector), row))
        scored.sort(key=lambda pair: (-pair[0], pair[1]['chunk_id']))
        total = len(scored)
        window = scored[offset_i:offset_i + limit_i]
        results = [self._row_to_record(row, score=round(score, 8))
                   for score, row in window]
        return {'total': total, 'limit': limit_i, 'offset': offset_i,
                'results': results}

    def count(self, filters=None):
        """Number of chunks matching validated filters."""
        validated = _validate_filters(filters)
        clauses, params = _where_for(validated)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        with _connect(self.db_file) as connection:
            _ensure_schema(connection)
            return connection.execute(
                f'SELECT COUNT(*) FROM knowledge_chunks{where}',
                tuple(params)).fetchone()[0]

    def stats(self):
        """Bounded index statistics for admin/health views."""
        with _connect(self.db_file) as connection:
            _ensure_schema(connection)
            chunks = connection.execute(
                'SELECT COUNT(*) FROM knowledge_chunks').fetchone()[0]
            documents = connection.execute(
                'SELECT COUNT(DISTINCT document_id) FROM knowledge_chunks').fetchone()[0]
            by_type = {
                row['document_type']: row['chunks']
                for row in connection.execute(
                    'SELECT document_type, COUNT(*) AS chunks FROM knowledge_chunks '
                    'GROUP BY document_type ORDER BY document_type')}
            dimensions = self._meta(connection, 'dimensions')
            model = self._meta(connection, 'embedding_model')
        return {
            'chunks': chunks,
            'documents': documents,
            'by_document_type': by_type,
            'dimensions': int(dimensions) if dimensions else None,
            'embedding_model': model,
            'schema_version': SCHEMA_VERSION,
        }

    def set_embedding_model(self, model):
        """Record the embedding model identifier used for (re)indexing."""
        if not isinstance(model, str) or not model.strip() or len(model) > 128:
            raise VectorStoreError('model must be a short non-empty string')
        with _connect(self.db_file) as connection:
            _ensure_schema(connection)
            self._set_meta(connection, 'embedding_model', model.strip())


def _cosine(vector_a, vector_b):
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for value_a, value_b in zip(vector_a, vector_b):
        dot += value_a * value_b
        norm_a += value_a * value_a
        norm_b += value_b * value_b
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


def _content_hash(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()
