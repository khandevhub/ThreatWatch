# ThreatWatch — Mini SOC

A local security-monitoring demo: JSONL or authenticated HTTP events are normalized, processed by deterministic demo rules, stored in SQLite, and shown in a Flask dashboard. This remains a simulated-data foundation; it does not collect real operating-system, endpoint, network, DNS, web, PowerShell, or cloud logs.

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

## Existing detections

| Rule | Event type | Trigger | Severity |
|---|---|---|---|
| `BRUTE_FORCE` | `auth_failed` | At least 5 failures from the same source IP within 60 seconds by default | HIGH |
| `PORT_SCAN` | `port_scan` | Any supplied `port_scan` event | MEDIUM |
| `TRAFFIC_SPIKE` | `traffic_spike` | Any supplied `traffic_spike` event | LOW |

Known-IP enrichment is loaded from `threat_intel.csv` at startup. These rules consume normalized/simulator events; real source collection and broader detection are not implemented.

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
| `PORT` | `5000` | Local Waitress port when running `python app.py` |

## Tests and project layout

```bash
uv run --locked --group dev python -m pytest -q
uv run --locked --group dev pip-audit
```

The suite covers event validation, database creation/migration, restart-safe collection and deduplication, the current deterministic rules and threat-intel enrichment, API authentication/errors, simulator/API end-to-end behavior, dashboard safety, and path handling.

Important files: `event_model.py` (versioned validation/normalization), `database.py` (authoritative SQLite schema and durable cursors), `collector.py` (JSONL tail and quarantine), `detector.py` (existing rules), `app.py` (dashboard API and protected ingestion), `simulator/` (catalog/writers), `templates/` and `static/` (dashboard), `tests/`, `compose.yaml`, and `Dockerfile`.

## Current limitations

- Only simulator/JSONL events and authenticated event POSTs are ingested; real log parsing is not implemented.
- Detection rules remain the three existing demo rules. Traffic spikes still fire on event type, not a measured baseline.
- Threat intelligence remains a small static IP/tag CSV without feed lifecycle, confidence, source history, or expiry.
- Dashboard and read-only alert APIs have no user accounts/RBAC; keep them on loopback or add an authenticated access layer before any remote exposure.
- SQLite and the in-process rate limiter are for a single local deployment, not a multi-node service.
- No incidents/cases, ATT&CK, Sigma, anomaly/ML, RAG/LLM, or response automation are included in this foundation phase.
