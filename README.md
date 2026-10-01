# ThreatWatch — Mini SOC

A local security-monitoring demo: JSONL or authenticated HTTP events are normalized, processed by a modular deterministic detection engine, correlated, scored with an explainable risk model, prioritized by the advisory **Jev** structured-decision layer (optional), stored in SQLite, and shown in a Flask dashboard. This remains a simulated-data project; it does not collect real operating-system, endpoint, network, DNS, web, PowerShell, or cloud logs.

> **Jev is an advisory structured-decision layer. It is not the primary detection
> engine and cannot execute security actions.** Deterministic detection, risk
> scoring, alerting, and persistence all run with Jev disabled, unavailable, or
> misconfigured; the layer only annotates alerts with a bounded priority,
> likelihoods, an investigation flag, and an attack category.

## Phase 2 — SOC core at a glance

```
RAW / INGESTED EVENTS (JSONL collector or POST /api/ingest)
      ↓
NORMALIZED EVENTS   event_model.SecurityEvent (validated, schema_version 1)
      ↓
DETERMINISTIC DETECTION   detections.DetectionEngine + rules registry (10 rules)
      ↓
THREAT INTELLIGENCE   threat_intel.ThreatIntel (offline CSV, typed indicators)
      ↓
CORRELATION   correlator.Correlator (indicator grouping + cooldown suppression)
      ↓
DETERMINISTIC RISK SCORE   risk.compute_risk (weighted factors, explainable)
      ↓
JEV STRUCTURED DECISION   decision.DecisionProvider (Jev | Mock | disabled)
      ↓
ALERT PRIORITIZATION   alerts table (risk band + Jev priority)
      ↓
INVESTIGATION   investigation_status lifecycle (new → investigating → resolved/dismissed)
```

Detection architecture: every rule is declared once in `rules.py` (id, name,
stable alert code, severity, threshold, window, confidence, tags, MITRE ATT&CK
mapping) and implemented in `detections.py`. Rules are independently testable,
individually disableable via `RULE_<ID>_ENABLED=false`, and tunable via
`RULE_<ID>_THRESHOLD`, `RULE_<ID>_WINDOW`, and `RULE_<ID>_SEVERITY`. Thresholds
and windows are deterministic; Jev adds advisory metadata only.

## Phase 3 — AI SOC investigation layer at a glance

```
STORED SOC ALERT
      ↓
EVIDENCE MODEL   evidence.py (secret redaction, bounded timeline, typed entities)
      ↓
INVESTIGATION PACKAGE   investigation.py (risk, entities, threat intel, ATT&CK,
      ↓                  related alerts, analyst questions — deterministic JSON)
ADVISORY AI PERSPECTIVE   investigation_provider.py (mock | disabled; offline)
      ↓
DASHBOARD PANEL   static/dashboard.js (text-node rendering, Investigate toggle)
      ↓
LIFECYCLE & AUDIT   app.py + database.py v3 (transition matrix, audit table)
      ↓
THREAT HUNTING   hunting.py (GET /api/hunt — whitelisted, parameterized, bounded)
```

Everything in Phase 3 is offline and deterministic by default: the only AI is a
mock provider that derives its output from the package itself, and enabling it
(`INVESTIGATION_AI_ENABLED=1`) never produces network calls. See
"Investigation and hunting (Phase 3)" below for details.

## Phase 4 — RAG foundation at a glance

```
KNOWLEDGE SOURCES (rules, ATT&CK, intel CSV, guides, incidents, docs)
      ↓
DOCUMENT NORMALIZATION   knowledge.py (typed documents, redaction, stable IDs)
      ↓
DETERMINISTIC CHUNKING   bounded chunks with overlap, stable chunk IDs
      ↓
EMBEDDINGS   embeddings.py (offline hashing provider; provider seam)
      ↓
VECTOR STORE   vector_store.py (SQLite-backed, persistent, filterable)
      ↓
RETRIEVER   retrieval.py (bounded top-k, metadata filters, deterministic)
      ↓
RAG CONTEXT   structured {query, retrieved_documents, evidence, metadata}
      ↓
[ FUTURE LLM INVESTIGATION — NOT IMPLEMENTED YET ]
```

**LLM investigation is not implemented yet.** Phase 4 builds only the
provider-neutral retrieval foundation: it stores, searches, and packages
data. It generates no answers, makes no LLM calls, adds no AI SDKs, and
leaves Jev and the Phase 3 advisory provider exactly as they were.

See "Knowledge retrieval and RAG foundation (Phase 4)" below for details.

## Requirements and reproducible setup

ThreatWatch supports Python 3.12 and 3.13 (`>=3.12,<3.14`). Use [uv](https://docs.astral.sh/uv/) to install the exact dependency graph in `uv.lock`, including test tools:

```bash
uv python install 3.12
uv sync --locked --group dev
uv run python -m pytest -q
```

`pyproject.toml` defines runtime and development dependencies; `uv.lock` is the reproducible environment lock. `requirements.txt` is the pinned runtime-only pip manifest; `requirements-dev.txt` adds test/audit tools for pip-based environments.

## Local demo

Use two terminals from the repository root:

```bash
uv run python collector.py
uv run python app.py
```

The dashboard is available at http://127.0.0.1:5000. The collector creates `simulated_logs.jsonl` with the demo catalog on first run and durably processes complete JSONL lines. Existing file content is processed from the beginning on first use; its SQLite cursor prevents replay after a restart. File rotation, truncation, and a changed last processed line start a new file generation. Malformed file records are recorded in `ingestion_errors` before advancing the cursor.

Append demo events with any of these:

```bash
uv run python simulate_attacks.py
uv run python simulate_attacks.py --out mylog.jsonl
uv run python simulate_attacks.py --delay 0.5
```

Windows users can run `simulate_attack_windows.bat`; Linux/macOS users can run `./simulate_attacks.sh`. Both use the shared Python simulator and append events.

## Authenticated HTTP ingestion

`POST /api/ingest` accepts one JSON event per request. Configure a random token of at least 32 characters in both the API and simulator environment. For example:

```bash
# PowerShell
$env:INGEST_TOKEN = (python -c "import secrets; print(secrets.token_urlsafe(32))")

# Bash
export INGEST_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Start the API in one terminal:

```bash
uv run python app.py
```

In a second terminal, set the same token and send the catalog:

```bash
uv run python simulate_attacks.py --target ingest
```

The client sends `Authorization: Bearer <token>`. Tokens may be supplied using `INGEST_TOKEN` or `INGEST_TOKEN_FILE`; configure only one. A missing token disables ingestion with HTTP 503. Invalid/missing credentials return 401, invalid JSON/events return 400, non-JSON content returns 415, payloads above 1 MiB return 413, and the local in-memory ingest limit returns 429. Use HTTPS for non-loopback destinations; the demo client refuses to send bearer tokens over non-local HTTP.

Every API event must include a stable `event_id`; this lets the server distinguish a retry from a new, identical event. Replaying an identical ID returns a duplicate response; reusing it for different event data returns HTTP 409. The legacy JSONL adapter generates IDs from file identity, generation, and byte offset.

## Event contract

The current version is `schema_version: 1`. `event_type` is required. The HTTP API requires `event_id`; the legacy file adapter generates one, and `source` defaults to the adapter. `event_time` accepts ISO-8601 timestamps and legacy `time`; naive timestamps are interpreted as UTC. `ingestion_time` is always assigned by the server. IPs and ports are validated and IPs canonicalized. Unknown fields, unsupported versions, invalid timestamps, invalid addresses, and malformed metadata are rejected.

The model includes `source_type`, `host`, `user`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `event_type`, `action`, `outcome`, `process`, `command_line`, `domain`, `url`, `file_hash`, and `metadata`. Source families include authentication, process, network, DNS, web, PowerShell, endpoint, and cloud identity. These are schema capabilities, not implemented collectors or detections.

Legacy simulator input remains supported: `type`, `time`, `src`, `ports`, `bytes`, and `message` are normalized; current `auth_failed`, `port_scan`, and `traffic_spike` rules remain unchanged in scope. Event insertion, deduplication, temporal failed-login state, alert creation, and enrichment use SQLite transactions. SQLite schema setup and upgrades use one `database.init_db()` path and `PRAGMA user_version`.

## Docker Compose

Docker Compose runs the dashboard and collector as separate non-root services sharing a persistent SQLite/input volume. The published dashboard port is bound to host loopback only. Docker access requires an `INGEST_TOKEN` in the host environment:

```bash
# Set INGEST_TOKEN using one of the commands above, then:
docker compose up --build
```

Open http://127.0.0.1:5000. To send events from the host, set the same token in the simulator environment and run `uv run python simulate_attacks.py --target ingest`. Stop with `docker compose down`; data remains in the named `threatwatch-data` volume. `docker compose down -v` deletes that volume and its data.

The dashboard and read-only alert APIs are intentionally a local demo boundary, not an internet-facing deployment. Do not bind or proxy them publicly without adding user authentication/authorization and TLS. The ingestion endpoint itself is bearer-token protected.

## Detection rules (Phase 2)

| Rule ID | Alert code | Event type | Trigger | Default severity | ATT&CK |
|---|---|---|---|---|---|
| `TW-001` | `BRUTE_FORCE` | `auth_failed` | ≥5 failures from one source within 60s (tunable) | HIGH | T1110 |
| `TW-002` | `PORT_SCAN` | `port_scan` | Any port-scan event | MEDIUM | T1046 |
| `TW-003` | `TRAFFIC_SPIKE` | `traffic_spike` | Any traffic-spike event | LOW | — |
| `TW-004` | `PASSWORD_SPRAYING` | `auth_failed` | ≥3 distinct usernames from one source within 300s | HIGH | T1110.003 |
| `TW-005` | `SUSPICIOUS_POWERSHELL` | `powershell_script` | Encoded commands, hidden-window flags, download cradles, remote-content execution | HIGH | T1059.001, T1027 |
| `TW-006` | `SUSPICIOUS_COMMAND_LINE` | `process_start` | Reverse shells, curl/wget-pipe-shell, account creation, schtasks/registry persistence, log clearing, credential-dump tools | MEDIUM | T1059 |
| `TW-007` | `SUSPICIOUS_PROCESS` | `process_start` | ncat/nc/socat/nmap/hydra/john/hashcat execution | MEDIUM | T1059.004 |
| `TW-008` | `SUSPICIOUS_PRIVILEGE` | `process_start` | sudo-family binaries, sudoers edits, wheel-group additions, local-admin additions | HIGH | T1548.003, T1078.003 |
| `TW-009` | `SUSPICIOUS_PERSISTENCE` | `process_start` | crontab modification, systemd service installation, systemd-run timers | HIGH | T1053.003, T1543.002 |
| `TW-010` | `POSSIBLE_EXFILTRATION` | `dns_query` | DNS look-alikes of internal naming (corp/internal/finance/… TLDs) | MEDIUM | T1048.003 |

Brute force and spraying share one windowed state store (`failed_login_attempts`)
and are deliberately distinguished: one account hammered = brute force; many
distinct accounts from one source = spraying. A merged correlation group carries
both rules' evidence when both fire. These rules consume normalized/simulator
events; real source collection is not implemented — PowerShell, process, and DNS
rules fire only on events supplied through the API/JSONL contract.

## Threat intelligence

`threat_intel.csv` (or `THREAT_INTEL`) supports `indicator,tag[,confidence[,source]]`.
The Phase 1 `ip,tag` format still loads. Indicators are classified automatically
as `ip` (IPv4/IPv6), `domain`, `url`, or `hash` (MD5/SHA1/SHA256 lengths).
Enrichment results carry `indicator`, `indicator_type`, `known_malicious`,
`confidence` (0.0–1.0, default 0.5 for legacy rows), and `source`.

## Correlation, risk, and the Jev decision layer

**Correlation** (`correlator.py`): findings sharing an attacker indicator
(source IP → domain → host) are grouped per event, evidence is merged (users,
hosts, event IDs, rule IDs, ATT&CK techniques), and each group receives a
`correlation_id`. A cooldown table (`alert_suppression`) suppresses duplicates:
a merged group escalates when any contributing rule has not yet alerted for that
indicator, and stays silent only when all of them have. `CORRELATION_ENABLED=false`
disables suppression entirely.

**Risk scoring** (`risk.py`): a deterministic 0–100 weighted sum — severity (30),
threat-intel confidence (25), distinct affected users (15, saturating at 5),
event frequency (15, saturating at 40), affected hosts (10, saturating at 3),
detector confidence (5). Every alert stores its factor breakdown and a plain
explanation; bands are low (<35), medium, high (≥60), critical (≥80).

**Jev** (`decision.py`): after risk scoring, ThreatWatch can ask the OpenCode Zen
System One model `jev-1.13-free` five bounded questions about the alert state —
priority, malicious likelihood, false-positive likelihood, investigation flag,
and attack category. One request covers all five; responses are validated against
a whitelist (invalid values fall back to `unknown`/defaults or raise for
rejection), the API key is read only from `JEV_API_KEY` and never logged, and
failures return a safe fallback (`priority=medium`, `investigation_required=true`,
`jev_status=fallback`). Jev can also be swapped for a deterministic
`MockDecisionProvider` in tests. The decision is advisory metadata on the alert;
it never blocks ingestion or detection.

| Variable | Default | Meaning |
|---|---|---|
| `JEV_ENABLED` | `false` | Enable the Jev decision provider |
| `JEV_MODEL` | `jev-1.13-free` | Model name sent to the endpoint |
| `JEV_TIMEOUT_SECONDS` | `10` | Request timeout (0–120) |
| `JEV_API_KEY` | unset | Bearer key for the endpoint; never logged |
| `JEV_ENDPOINT` | `https://opencode.ai/zen/v1/systemone` | Override for testing |
| `CORRELATION_ENABLED` | `true` | Master switch for suppression/escalation |
| `CORRELATION_COOLDOWN_SECONDS` | `300` | Duplicate-alert window per (rule, indicator) |
| `SPRAY_MIN_USERS` | `3` | Distinct usernames before spraying fires |
| `SPRAY_WINDOW` | `300` | Spray window in seconds |
| `RULE_<ID>_ENABLED` | `true` | Enable/disable one rule (e.g. `RULE_TW_005_ENABLED`) |
| `RULE_<ID>_THRESHOLD` | per rule | Override one rule's threshold |
| `RULE_<ID>_WINDOW` | per rule | Override one rule's window (seconds) |
| `RULE_<ID>_SEVERITY` | per rule | Override one rule's severity |

Example spray scenario: `uv run python simulate_attacks.py --scenario spray`
appends eight auth failures across four users plus a suspicious PowerShell event;
the pipeline produces spraying and PowerShell alerts with risk, correlation, and
(fallback) decision metadata.

### Investigation lifecycle

Every SOC alert starts with `investigation_status = new`. An authenticated client
can progress it: `POST /api/alerts/<id>/status` with `{"status": "investigating"}`
(or the Phase 2 aliases `"in_progress"`/`"closed"`, which canonicalize on storage;
same bearer token as ingestion). Transitions follow a deterministic matrix —
`new → investigating/resolved/dismissed`, `investigating → investigating/resolved/dismissed`,
`resolved → investigating/dismissed`, `dismissed → investigating` — and every
accepted transition writes an `investigation_events` audit row (from/to status,
timestamp, source). Invalid transitions are rejected with HTTP 409, unknown
statuses with 400, and missing alerts with 404. The dashboard shows status on
each alert card; `GET /api/alerts` returns the full SOC view (risk score/band/
factors/explanation, Jev metadata, ATT&CK techniques, evidence, source event IDs,
correlation ID, status).

## Investigation and hunting (Phase 3)

Phase 3 turns a stored alert into an analyst-ready investigation package, adds a
bounded threat-hunting query layer, and an advisory AI-provider seam — all local,
deterministic, and offline by default. No RAG, embeddings, vector store, or
external AI calls are introduced.

**Evidence model** (`evidence.py`): every free-text field passes `redact_text`,
which masks passwords/API keys/tokens (`key=value` forms and `Bearer …` headers),
replaces private-key blocks, and bounds length. `build_timeline` orders events
deterministically (timestamp → event ID; missing timestamps sort last and are
flagged) and is capped at 100 entries. `Evidence` carries typed entity lists
(IPs, hosts, users, processes, commands, domains, URLs, hashes) and an explicit
`unavailable` list instead of invented values.

**Investigation packages** (`investigation.py`): `GET /api/alerts/<id>/investigation`
returns one alert's package: alert view, risk score/band/factors/explanation,
evidence with entities, ordered timeline, indicators (with `known_malicious`
flags), threat-intelligence context (stored enrichment plus current feed matches),
MITRE ATT&CK context (stored mappings only, labeled with canonical technique
names and per-technique suggested next steps; merged alerts attribute each
technique to the member rule that maps to it), related alerts (same correlation
first, then same-rule history), and deterministic analyst questions. Packages are
JSON-serializable, bounded, deterministic, and secret-safe; unknown alerts return 404.

**Hunting** (`hunting.py`): `GET /api/hunt` runs a whitelisted, parameterized query
over stored events. Filters: exact (`src_ip`, `dst_ip`, `event_type`, `file_hash`),
substring (`user`, `host`, `process`, `command`, `domain`, `url`; LIKE wildcards
escaped, character allowlist), time (`time_from`/`time_to`, semantically validated
ISO-8601), and linkage (`alert_id`, `correlation_id`, `technique` — the technique
match is quote-delimited so `T1110` never matches `T1110.003`). Unknown filters,
unsafe values, and bad paging fail closed with 400. Results are ordered by
`(event_time, event_id)`, paginated (`limit` ≤ 500), secret-redacted, and an
unknown `alert_id` yields an empty set — never an unfiltered query.

**AI provider seam** (`investigation_provider.py`): `InvestigationProvider`
defines `investigate`/`summarize`/`generate_hypotheses`. Phase 3 ships two offline
implementations: `MockInvestigationProvider` (deterministic summaries/hypotheses
derived only from the package) and `DisabledInvestigationProvider` (the default).
`INVESTIGATION_AI_ENABLED=1` selects the mock; packages gain an `ai_perspective`
section whose status is `disabled`, `ok`, or `unavailable` (provider failures are
downgraded to `unavailable`, never breaking the package). No network calls are
made from this layer; Jev remains the separate decision layer.

**Lifecycle and audit** (`database.py`, `app.py`): schema v3 adds the
`investigation_events` audit table (cascade-deleted with its alert) and a migration
that canonicalizes Phase 2 `in_progress`/`closed` values to
`investigating`/`resolved`.

**Dashboard**: each alert card gains an Investigate toggle that renders the
canonical package sections (status, risk, entities, unavailable evidence, threat
intel, ATT&CK, related alerts, first ten timeline entries, suggested next steps)
using text nodes only — no `innerHTML`, no template changes.

## Knowledge retrieval and RAG foundation (Phase 4)

Phase 4 adds a local, offline retrieval layer over ThreatWatch's own security
knowledge so a future LLM investigation layer can be fed structured context.
Everything is deterministic, bounded, and secret-safe; no new third-party
dependencies are introduced.

**Vector storage** (`vector_store.py`): a provider-neutral `VectorStore` on top
of SQLite (file `knowledge.sqlite`, separate from the SOC database). Chunks
carry the embedding (JSON float vector), document ID, chunk ID, document type,
source, title, structured metadata (`mitre_techniques`, `rule_id`, `alert_id`,
`timestamp`), and content hashes. `upsert`/`delete`/`delete_document`/`get`/
`get_document_chunks`/`search`/`count`/`stats` are the whole API. Search is
cosine similarity computed in-process — fast for the bounded local indexes this
project targets (hundreds to low thousands of chunks) — with deterministic
ordering (score DESC, then chunk ID) and hard limits (top-k ≤ 50). The first
write locks the store's dimensionality; mismatched vectors fail closed.
Metadata filters are whitelisted and validated exactly like the Phase 3 hunt
filters (`document_type`, `source`, `technique`, `rule_id`, `alert_id`,
`time_from`/`time_to`; quote-delimited technique matching so `T1110` never
matches `T1110.003`); unknown filters are rejected.

**Embeddings** (`embeddings.py`): an `EmbeddingProvider` interface
(`embed_text`/`embed_many`/`describe`) with three offline implementations.
The default is `disabled` (embedding off). `local` selects the deterministic
`local-hash` provider — a hashed bag-of-words+bigrams embedding (blake2b,
sign-hashed, L2-normalized, 8–2048 dimensions, default 256) with no model
download, no GPU, and identical vectors across runs and platforms. `mock`
provides tiny fixed-vocabulary vectors for tests. Indexing defaults to the
local provider so admin indexing works without configuration.

**Knowledge ingestion** (`knowledge.py`): explicit sources only — detection
rules and their ATT&CK mappings (from the rule registry), per-technique MITRE
documents, the threat-intel CSV (parsed structurally, never as raw text),
deterministic investigation guides (per-rule and lifecycle), historical
resolved/dismissed alert summaries (structural fields only, no free text), and
a fixed allowlist of repository documentation (`README.md`, `LICENSE.txt`).
Nothing can be ingested from caller-supplied paths. Every text passes
`redact_text` before chunking, hashing, or embedding, so credentials and
key=value secrets (including prefixed names like `INGEST_TOKEN=`) are never
indexed. Document types: `detection_rule`, `mitre_technique`,
`threat_intelligence`, `investigation_guide`, `historical_incident`,
`project_documentation`. Documents carry stable IDs, content hashes, versions,
and classification metadata.

**Chunking**: deterministic paragraph-first splitting (then sentences, then
hard cuts) with bounded size (800 chars), overlap (120), and stable chunk IDs
(`<document_id>#<index>`). Re-ingesting unchanged content rewrites the same
rows — idempotent; changed content updates its chunks and stale chunks from a
larger previous version are removed.

**Retrieval** (`retrieval.py`): `KnowledgeRetriever` embeds a validated query
(≤ 512 chars), searches the store, and returns bounded top-k results (default
5, max 20) with scores, sources, chunk/document IDs, and metadata — ordered
deterministically. `build_rag_context` packages retrieval results plus live
investigation evidence into one JSON-serializable structure: `query`,
`retrieved_documents` (origin `knowledge_base`, marked untrusted), `evidence`
(origin `live_investigation`), `sources`, and `metadata` including an explicit
usage note that retrieved documents are untrusted data, never instructions.
The builder generates no answers, fabricates nothing, bounds every snippet and
the total context, and re-redacts defensively.

**API** (read-only): `GET /api/knowledge/search?q=<query>&top_k=<k>&<filters>`
returns bounded retrieval results (400 on invalid queries/filters). The
investigation endpoint accepts `?with_knowledge=1` to attach a
`knowledge_context` section; retrieval failures degrade to
`status=unavailable` and never break the package. There are no write endpoints:
indexing stays a local admin operation.

**Admin CLI** (`knowledge_admin.py`):

```bash
uv run python knowledge_admin.py index          # ingest/reindex all sources (idempotent)
uv run python knowledge_admin.py stats          # chunk/document counts by type
uv run python knowledge_admin.py search "password spraying" --top-k 3 \
    --filter document_type=detection_rule       # bounded retrieval test
```

`--db` selects the vector store file (default `KNOWLEDGE_DB_FILE` or
`knowledge.sqlite`); `--soc-db` selects the SOC database for historical
incidents (default `DB_FILE` or `db.sqlite`).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DB_FILE` | `db.sqlite` | SQLite database path |
| `SIM_FILE` | `simulated_logs.jsonl` | JSONL file watched by the collector |
| `THREAT_INTEL` | `threat_intel.csv` | Demo `ip,tag` CSV |
| `DETECTION_WINDOW` | `60` | Brute-force window in seconds; positive integer |
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed-logins threshold; positive integer |
| `INGEST_TOKEN` | unset | Bearer token; at least 32 characters when set |
| `INGEST_TOKEN_FILE` | unset | File containing the bearer token; mutually exclusive with `INGEST_TOKEN` |
| `INVESTIGATION_AI_ENABLED` | `false` | Attach the offline mock AI perspective to investigation packages |
| `KNOWLEDGE_DB_FILE` | `knowledge.sqlite` | Vector-store database path (Phase 4) |
| `EMBEDDING_PROVIDER` | `disabled` | Query embedding provider: `disabled`, `local`, or `mock` |
| `EMBEDDING_DIMENSIONS` | `256` | Local hashing-embedding dimensions (8–2048) |
| `LOCAL_EMBEDDING_PROVIDER` | `local-hash` | Concrete offline provider behind `EMBEDDING_PROVIDER=local` |
| `PORT` | `5000` | Local Waitress port when running `python app.py` |

## Tests and project layout

```bash
uv run --locked --group dev python -m pytest -q
uv run --locked --group dev pip-audit
```

The suite covers event validation, database creation/migration (including the
Phase 3 status canonicalization), restart-safe collection and deduplication, the
current deterministic rules and threat-intel enrichment, API authentication/errors,
simulator/API end-to-end behavior, dashboard safety, path handling, the Phase 3
evidence/redaction model, investigation packages, hunting (filters, limits,
SQL-injection attempts), lifecycle transitions/audit, provider seam, a full
Phase 3 end-to-end flow, and the Phase 4 vector store (persistence, dimension
locking, filters), embedding providers (determinism, bounds, failure), knowledge
ingestion (sources, idempotence, redaction, stable IDs), chunking, retrieval
(filters, top-k bounds, deterministic ordering), the RAG context package,
knowledge API integration, Phase 4 security (injection-as-data, secrets, path
safety), and a full Phase 4 end-to-end flow.

Important files: `event_model.py` (versioned validation/normalization), `database.py` (authoritative SQLite schema, v3, and durable cursors), `collector.py` (JSONL tail and quarantine), `rules.py` (rule registry/metadata and ATT&CK technique names), `detections.py` (detection engine), `threat_intel.py` (indicator classification/enrichment), `correlator.py` (grouping/suppression), `risk.py` (explainable scoring), `decision.py` (Jev provider abstraction), `detector.py` (pipeline orchestration), `evidence.py` (redaction/timeline/evidence model), `investigation.py` (investigation packages), `hunting.py` (bounded hunt queries), `investigation_provider.py` (advisory AI seam), `vector_store.py` (SQLite vector store), `embeddings.py` (offline embedding providers), `knowledge.py` (ingestion/chunking), `retrieval.py` (retriever/RAG context), `knowledge_admin.py` (index admin CLI), `app.py` (dashboard API, protected ingestion, investigation lifecycle/endpoints, knowledge search), `simulator/` (catalogs/writers), `templates/` and `static/` (dashboard), `tests/`, `compose.yaml`, and `Dockerfile`.

## Current limitations

- Only simulator/JSONL events and authenticated event POSTs are ingested; real log parsing is not implemented. The PowerShell, process, privilege, persistence, and DNS rules fire only when such events are supplied through the event contract.
- Traffic spikes still fire on event type, not a measured baseline.
- Threat intelligence remains a small static CSV without feed lifecycle, expiry, or history; enrichment is exact-match only.
- Correlation is indicator-based within the SQLite/local deployment; there is no distributed streaming, and suppression state is per-database.
- Jev is advisory only; there is no autonomous response, blocking, or SOAR. Phase 3 adds a deterministic offline AI-perspective seam only — no chatbot or external AI calls in the investigation layer.
- The Phase 4 retrieval foundation is a data layer only: LLM investigation is **not implemented yet**, there are no external embedding/AI calls, and the `local-hash` embedding is a deterministic bag-of-features substitute, not a semantic transformer model — retrieval quality reflects term overlap, not deep semantics.
- The vector store is a single-file SQLite index with in-process cosine search; it is not a distributed or approximate-nearest-neighbor engine, and indexes are per-database file.
- Knowledge ingestion is bounded to explicit sources (rules, ATT&CK mappings, local intel CSV, generated guides, structural incident summaries, and the fixed README/LICENSE allowlist); it does not crawl arbitrary repositories or files.
- Dashboard and read-only alert APIs have no user accounts/RBAC; keep them on loopback or add an authenticated access layer before any remote exposure.
- SQLite and the in-process rate limiter are for a single local deployment, not a multi-node service.
- The hunting layer is exact/substring over stored events with alert linkage; there is no Sigma parser, saved-query workbench, cross-database federated search, or case management.
