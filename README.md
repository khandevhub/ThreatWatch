# ThreatWatch — Mini SOC (Pro Edition)
**Author:** Amanullah Khan

## What's new (Pro Edition)
- Polished dashboard with counts, severity badges, and charts (no build tools required)
- Threat intelligence integration (flags known malicious IPs from `intel/blacklist.csv`)
- Auto-updating UI (polling) with filters by severity/type
- Unit tests for detector rules and threat-intel
- GitHub Actions CI workflow to run tests automatically
- Included demo screenshots (`screenshots/`) and a short demo GIF (`screenshots/demo.gif`)

## Quick start (same as before)
1. Extract the repo and `cd ThreatWatch_Pro`
2. Create and activate a Python venv:
   - `python3 -m venv venv`
   - `source venv/bin/activate` (Linux/macOS/WSL) or `venv\Scripts\activate` (Windows)
3. Install requirements:
   - `pip install -r requirements.txt`
4. Run the collector (terminal 1):
   - `python collector.py`
5. Run the app (terminal 2):
   - `python app.py`
6. Generate simulated attacks (terminal 3):
   - `bash simulate_attacks.sh` (or `simulate_attack_windows.bat` on Windows)
7. Open `http://127.0.0.1:5000` in your browser and watch alerts and charts update.

## Key files
- `app.py` — Flask app serving API and dashboard
- `collector.py` — log ingestion (processes simulated or real logs)
- `detector.py` — detection engine; now checks threat-intel and flags events
- `intel/blacklist.csv` — simple CSV of known malicious IPs (sample)
- `simulate_attacks.sh` — generates simulated events for demo
- `templates/dashboard.html` — improved UI with Chart.js (CDN)
- `tests/` — pytest tests
- `.github/workflows/ci.yml` — GitHub Action to run pytest on push
- `screenshots/` — included images and demo GIF for GitHub readme preview

## Threat detection rules (summary)
- BRUTE_FORCE: >= BRUTE_FORCE_THRESHOLD failed auth events from same IP inside DETECTION_WINDOW -> HIGH.
- PORT_SCAN: port_scan event -> MEDIUM.
- TRAFFIC_SPIKE: traffic_spike event with bytes above threshold -> LOW.
- KNOWN_THREAT: any event from an IP present in `intel/blacklist.csv` will be flagged and severity bumped.

## Notes for interviews
- Start collector, app, then run simulate script. Show the dashboard: counters, pie chart, timeline, and the alert entries with KNOWN_THREAT badges for malicious IPs.
- Explain pipeline: logs -> collector -> detector (+intel) -> DB -> API -> dashboard.
- All attacks simulated locally for demo; do not run scans against external systems.
