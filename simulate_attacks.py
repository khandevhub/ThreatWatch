#!/usr/bin/env python3
# simulate_attacks.py - cross-platform demo event writer (Windows & Unix).
# Replaces the broken flow where the Windows .bat tried to run the Bash
# script through Python. The .sh remains for Unix users.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from simulator.append_events import main  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(main())
