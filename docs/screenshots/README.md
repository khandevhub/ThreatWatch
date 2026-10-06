# Dashboard screenshots

The README embeds the following screenshots, captured from the running
dashboard (headless Chromium at 1600×1000, dark theme) during one demo
session: fresh demo database, mock AI provider, Attack Replay + guided
SOC Demo + analyst case workflow, human approval gate, dry-run response.

| File | View | How to reproduce |
|---|---|---|
| `command-center.png` | Console top: status pills, counters, automation workers, SOC overview, severity/MITRE/source bars | Open the dashboard after `.\demo.ps1` |
| `alert-queue.png` | Alert queue with TW-001 rows (rule, correlation, severity, risk, Jev, AI, investigation) | Run Attack Replay and/or the guided SOC Demo |
| `attack-replay.png` | Attack Replay panel: `SYNTHETIC / LAB`, per-event steps, `DETECTION TRIGGERED` | Generate a brute-force scenario, start the replay |
| `alert-investigation.png` | Alert detail: WHY panel, decision chain, evidence timeline, questions, advisory AI panel, SOAR workflow, analyst case | Click an alert row in the queue |
| `why-panel.png` | WHY THREATWATCH ALERTED: detection, evidence checkmarks, risk-factor table, MITRE, Jev, AI, final state | Visible in every alert detail |
| `decision-chain.png` | Nine-stage decision chain with live stored states | Visible in every alert detail |
| `soar-defense-center.png` | SOAR Defense Center: playbooks, dry-run execution SUCCEEDED, resolved approval gate, incident | Run the guided SOC Demo and approve at the gate |
| `audit-trail.png` | SOC audit trail: workflow (approval → execution → success) + case events | After approval and the analyst case workflow |

Also under `docs/`:

- `docs/assets/threatwatch-architecture.svg` — pipeline architecture diagram
- `docs/demo/ThreatWatch-Demo.mp4` — full guided demo recording (1 min 49 s)
- `docs/demo/ThreatWatch-Demo.gif` — short animated preview of the demo

Never include console tokens, API keys, or real personal data in screenshots —
the dashboard masks the token field, and the demo launcher's token is
ephemeral, but double-check captures before publishing.
