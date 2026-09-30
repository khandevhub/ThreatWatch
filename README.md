# ThreatWatch — Mini SOC

A small, self-contained security-monitoring demo: a log-file collector feeds
events to a tiny detection engine, alerts are stored in SQLite, and a web
dashboard shows live alerts with severity counters and a per-rule chart.

## What ThreatWatch does today

- **Collector** (`collector.py`): watches `simulated_logs.jsonl` and processes
  each newly appended JSON line. Uses an incremental tail reader so appends are
  processed exactly once (no full-file reprocessing / duplicate alerts).
- **Detector** (`detector.py`): applies the detection rules below and writes
  alerts to SQLite (`db.sqlite` by default), with structured enrichment rows
  (`alert_enrichment` table).
- **Threat intel**: `threat_intel.csv` (header `ip,tag`) is loaded at startup;
  events from listed IPs get a `[KNOWN_SCANNER]`-style note in the alert
  details and a `known_threat=true` enrichment row.
- **Dashboard** (`app.py` + `templates/dashboard.html`): Flask app serving a
  single page that polls `/api/alerts` and `/api/summary` every 1.5 s, with
  severity counters, a severity filter, and a Chart.js bar chart. Alert text is
  rendered with safe DOM APIs (no HTML injection).
- **Simulator**: demo events for testing the whole pipeline
  (see *Running the demo*).

## Current detection rules

| Rule | Event type | Trigger | Severity |
|---|---|---|---|
| `BRUTE_FORCE` | `auth_failed` | >= 5 failed logins from the same source IP within 60 s | HIGH |
| `PORT_SCAN` | `port_scan` | any `port_scan` event (list of ports included) | MEDIUM |
| `TRAFFIC_SPIKE` | `traffic_spike` | any `traffic_spike` event (byte count included) | LOW |

Known-IP enrichment applies to all three rules. Counters/window/threshold are
configurable via environment variables (below).

## Installation

Requires Python 3.8+ (tested on 3.10).

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running it

1. **Start the detector+collector** (creates the DB and a sample event file on
   first run):

   ```bash
   python collector.py
   ```

2. **Start the dashboard** (in a second terminal):

   ```bash
   python app.py
   ```

   Then open http://127.0.0.1:5000

3. **Feed demo events**:

   - Windows: double-click `simulate_attack_windows.bat` (or run it from a
     shell) — it calls `python simulate_attacks.py`.
   - Linux/macOS: `./simulate_attacks.sh` (Bash version, same output).
   - Cross-platform CLI:

     ```bash
     python simulate_attacks.py                       # append to simulated_logs.jsonl
     python simulate_attacks.py --out mylog.jsonl     # custom output file
     python simulate_attacks.py --delay 0.5           # slower stream
     ```

The collector tail-watches the file, so appended events appear on the
dashboard within ~1.5 seconds. `db.sqlite` and `simulated_logs.jsonl` are
runtime artifacts and are gitignored.

### Docker

```bash
docker build -t threatwatch .
docker run -p 5000:5000 threatwatch
```

## How to run tests

```bash
python -m pytest -v
```

The suite covers the detector rules, known-IP enrichment, the alert DB API,
and the collector's tail reader (append/truncate handling, duplicate
processing regression).

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `DB_FILE` | `db.sqlite` | SQLite database path |
| `DETECTION_WINDOW` | `60` | Brute-force window (seconds) |
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed logins before a brute-force alert |
| `THREAT_INTEL` | `threat_intel.csv` | Threat-intel CSV path (`ip,tag`) |
| `SIM_FILE` | `simulated_logs.jsonl` | File the collector watches |
| `LOG_PATH` | `/var/log/auth.log` | Placeholder for future real-log ingestion |

## Project structure

```
ThreatWatch/
├── app.py                     Flask dashboard + JSON API
├── collector.py               watchdog-based collector, incremental tailing
├── detector.py                detection rules, SQLite alert store, enrichment
├── threat_intel.csv           known threat IPs (ip,tag)
├── simulate_attacks.py        cross-platform demo event writer (entry point)
├── simulate_attacks.sh        Bash wrapper (Unix)
├── simulate_attack_windows.bat Windows wrapper
├── simulator/
│   ├── catalog.py             shared demo event set
│   └── append_events.py       file-append / HTTP-ingest writer logic
├── templates/dashboard.html   dashboard UI (DOM-safe rendering)
├── static/style.css           dashboard styles
├── tests/                     pytest suite
├── requirements.txt           pinned dependencies
├── Dockerfile                 container image
└── db.sqlite                  (runtime, gitignored)
```

## Known limitations

- **No authentication/authorization** on the dashboard or API; anyone who can
  reach the port can read alerts. Bind it to localhost for demos.
- **Development server**: `app.py` runs Flask's built-in server with debug
  mode disabled; it is not a production WSGI deployment.
- **Simulated ingestion only**: despite `LOG_PATH`, real syslog/auth.log
  parsing is not implemented; events are JSON lines you append (or POST).
- **State is per-process**: brute-force counters live in the detector's memory
  and reset on restart; the collector must run in the same process family as
  the detector (it imports it).
- `TRAFFIC_SPIKE` fires on the event type alone (no baseline/threshold logic).
- No deduplication/aggregation across alerts, no case management, no
  retention policy, no HTTPS/TLS termination.
- Threat intel is a static CSV with no source/age/confidence metadata.
