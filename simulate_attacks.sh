#!/usr/bin/env bash
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
OUT="${1:-simulated_logs.jsonl}"
python "$SCRIPT_DIR/simulate_attacks.py" --target file --out "$OUT"
