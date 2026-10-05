# Dashboard screenshots

The README references the following screenshots, captured from the running
SOC Command Center (`http://127.0.0.1:5000/`, dark theme, 1600×1000):

| File | View | How to reproduce |
|---|---|---|
| `soc-command-center.png` | Full console top: status pills, counters, automation workers, SOC overview, severity/MITRE/source bars | Open the dashboard after `.\demo.ps1` |
| `alert-queue.png` | Alert queue with one TW-001 row (rule, correlation, severity, risk, Jev, AI) | Run the Brute Force Attack Replay |
| `alert-investigation.png` | Alert detail: entities, evidence timeline, investigation questions, advisory AI panel with RAG sources | Click an alert row |
| `why-panel.png` | WHY THREATWATCH ALERTED: detection, evidence checkmarks, risk-factor table, MITRE, Jev, AI, final state | Open any alert |
| `decision-chain.png` | Nine-stage decision chain with live states | Visible in every alert detail |
| `attack-replay.png` | Attack Replay panel mid-run: `SYNTHETIC / LAB`, per-event steps, DETECTION TRIGGERED | Start a replay with Slow pacing |
| `soar.png` | SOAR Defense Center: playbooks, DRY RUN executions, approval gate, incidents | Execute TW-PB-001 from an alert detail and approve |
| `audit-trail.png` | SOC audit trail: workflow + case events | After the case workflow (open → confirm → close) |

Never include console tokens, API keys, or real personal data in screenshots —
the dashboard masks the token field, and the demo launcher's token is
ephemeral, but double-check captures before publishing.
