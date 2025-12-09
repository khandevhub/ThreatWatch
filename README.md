📡 ThreatWatch — Mini SOC (Pro Edition)

A Lightweight Security Operations Center Pipeline Built for Real-World Detection

Developer: Amaan (aka khan dev hub)
Stack: Python · Flask · SQLite · Linux/WSL · Threat Intelligence · Chart.js

🚀 Overview

ThreatWatch is a Mini SOC platform that simulates a real detection pipeline:
log ingestion → detection engine → threat-intel correlation → alert storage → dashboard visualization.
Built to demonstrate hands-on SOC skills for internships and security engineering roles.

This project shows:

Real-time alerting

Detection of brute-force attacks, port scans, and outbound traffic spikes

Threat-intel enrichment (flags & escalates known malicious IPs)

A clean dashboard with charts + filters

A full E2E pipeline you can explain in interviews like a beast

Recruiters love this because it’s simple to run but architecturally legit.

🧩 Architecture Diagram
                +-----------------------+
                | simulate_attacks.sh   |
                |  or system logs       |
                +-----------+-----------+
                            |
                            v
                   +--------+--------+
                   |   collector.py  |
                   |  (parses logs)  |
                   +--------+--------+
                            |
                            v
                   +--------+--------+
                   |  detector.py    |
                   | applies rules + |
                   | threat intel    |
                   +--------+--------+
                            |
                            v
                   +--------+--------+
                   |  SQLite DB      |
                   |  (alerts)       |
                   +--------+--------+
                            |
                            v
                   +--------+--------+
                   |   Flask API     |
                   |  /api/alerts    |
                   +--------+--------+
                            |
                            v
                   +--------+--------+
                   |   Dashboard     |
                   | (charts + list) |
                   +-----------------+

🖥️ Dashboard Preview

Replace these placeholders with your own uploaded images
(GitHub → Upload screenshots into screenshots/ → copy link)

Before Alerts:


After Alerts:


Live Demo GIF:


🔥 Key Features
✔ Real Detection Rules

BRUTE_FORCE – detects repeated failed login attempts

PORT_SCAN – catches multiple probe attempts on common ports

TRAFFIC_SPIKE – flags suspicious spikes in outbound bandwidth

✔ Threat Intelligence Integration

Enriches alerts using intel/blacklist.csv

Automatically escalates severity to HIGH or CRITICAL

Adds flags like:
KNOWN_THREAT: 192.168.1.20

✔ Professional Dashboard

Severity filters

Attack counters

Pie chart distribution

Clean UI using Chart.js CDN (no heavy setup)

✔ SOC-Ready Pipeline

End-to-end processing: logs → detection → DB → API → dashboard

Simple, readable, interview-friendly code

⚙️ How to Run (3-Terminal SOC Demo)
Terminal 1 — Collector
python -u collector.py

Terminal 2 — Dashboard
python -u app.py

Terminal 3 — Generate Attacks
bash simulate_attacks.sh

View Dashboard
http://127.0.0.1:5000

🛡 Detection Logic Summary

Sliding time-window analysis for brute-force attempts

Port clustering & threshold detection for port scans

Byte-count thresholding for traffic anomalies

Intel correlation → severity escalation for malicious IP matches

This is exactly how junior SOC analysts investigate events in SIEM tools.

🧪 Testing

Unit tests inside /tests validate:

rule detection

intel escalation

alert generation format

Run tests:

pytest

📦 Project Structure
ThreatWatch_Pro/
│── app.py                # Flask dashboard + API
│── collector.py          # Log ingestion
│── detector.py           # Detection engine
│── requirements.txt
│── README.md
│── Dockerfile
│── intel/
│   └── blacklist.csv
│── templates/
│   └── dashboard.html
│── static/
│   └── dashboard.js
│── tests/
│── screenshots/
└── simulate_attacks.sh

🎯 Why This Project Impresses Recruiters

Shows true SOC workflow understanding, not just theory

Demonstrates Python, Flask, cyber detection logic, threat intel, dashboards

Clear architecture & readable code

Demo-ready in 30 seconds

Looks like something a junior SOC engineer would build in real life

This is the type of project that gets callbacks.

👤 Developer

Amaan — khandevhub
Cybersecurity Engineer (SOC / Threat Detection)
