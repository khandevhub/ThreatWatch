"""Structured, offline threat-intelligence loading and indicator enrichment.

Extends the Phase 1 ``ip,tag`` CSV with typed indicators and structured
enrichment results, while remaining fully backward compatible: the default
``threat_intel.csv`` still loads, and a header-only file still yields an
empty table. No external feeds or paid APIs are introduced.
"""
from __future__ import annotations

import csv
import ipaddress
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger('threatwatch.threat_intel')

MAX_FILE_BYTES = 4 * 1024 * 1024  # local CSV cap; keeps loading bounded
DEFAULT_CONFIDENCE = 0.5          # legacy rows without a confidence column


@dataclass(frozen=True)
class Enrichment:
    """Structured enrichment result for one indicator lookup."""

    indicator: str
    indicator_type: str          # ip | domain | url | hash
    known_malicious: bool
    confidence: float            # 0.0 - 1.0, tied to the feed row's confidence
    source: str

    def to_dict(self):
        return {
            'indicator': self.indicator,
            'indicator_type': self.indicator_type,
            'known_malicious': self.known_malicious,
            'confidence': self.confidence,
            'source': self.source,
        }


def _confidence(raw):
    """Parse a 0.0-1.0 confidence value; fall back to the legacy default."""
    if raw is None or raw == '':
        return DEFAULT_CONFIDENCE
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_CONFIDENCE
    if not 0.0 <= value <= 1.0:
        return DEFAULT_CONFIDENCE
    return value


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def classify_indicator(value):
    """Return the indicator type for a raw string, or None if unsupported."""
    text = str(value).strip()
    if not text or len(text) > 2048 or any(ord(char) < 33 for char in text):
        return None
    if _is_ip(text):
        return 'ip'
    lowered = text.lower()
    if lowered.startswith(('http://', 'https://')):
        return 'url'
    if len(text) in (32, 40, 64, 128) and all(
            char in '0123456789abcdefABCDEF' for char in text):
        return 'hash'
    if '.' in text and ' ' not in text:
        labels = text.rstrip('.').lower().split('.')
        if all(label and not label.startswith('-') and not label.endswith('-')
               for label in labels) and all(
               _is_label(label) for label in labels):
            return 'domain'
    return None


def _is_label(label):
    try:
        return label.isascii() and label.replace('_', 'a').isalnum()
    except Exception:
        return False


class ThreatIntel:
    """In-memory exact-match table of known-malicious indicators."""

    def __init__(self):
        # indicator -> (tag, confidence, source)
        self._table = {}

    def __len__(self):
        return len(self._table)

    def load_csv(self, path):
        """Load the extended CSV; tolerate the Phase 1 ``ip,tag`` format."""
        if not path or not os.path.exists(path):
            if path:
                logger.warning('Threat intel file not found: %s', path)
            return 0
        if os.path.getsize(path) > MAX_FILE_BYTES:
            logger.warning('Threat intel file too large, skipping: %s', path)
            return 0
        loaded = 0
        with open(path, 'r', encoding='utf-8-sig', newline='') as stream:
            for line_no, row in enumerate(csv.reader(stream), start=1):
                if not row:
                    continue
                indicator = (row[0] or '').strip()
                if not indicator or line_no == 1 and indicator.lower() in ('ip', 'indicator'):
                    continue
                indicator_type = classify_indicator(indicator)
                if indicator_type is None:
                    logger.debug('Skipping unparseable intel row %d', line_no)
                    continue
                tag = (row[1] if len(row) > 1 and row[1].strip() else '') or 'known_threat'
                confidence = _confidence(row[2] if len(row) > 2 else None)
                source = (row[3] if len(row) > 3 and row[3].strip() else '') or 'local_csv'
                self._table[indicator] = (tag, confidence, source)
                loaded += 1
        return loaded

    def lookup(self, indicator):
        """Return an Enrichment for the indicator (known_malicious=False if unseen)."""
        text = str(indicator or '').strip()
        indicator_type = classify_indicator(text)
        if indicator_type is None:
            return None
        row = self._table.get(text)
        if row is None:
            return Enrichment(
                indicator=text, indicator_type=indicator_type,
                known_malicious=False, confidence=0.0, source='none')
        tag, confidence, source = row
        return Enrichment(
            indicator=text, indicator_type=indicator_type,
            known_malicious=True, confidence=confidence, source=source)

    def tag(self, indicator):
        """Phase 1 compatibility: the feed tag for an IP, or None."""
        row = self._table.get(str(indicator or '').strip())
        return row[0] if row else None
