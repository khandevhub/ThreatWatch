@echo off
REM Windows-compatible demo event writer (the old version ran the Bash
REM script through python, which cannot work). Delegates to simulate_attacks.py.
python "%~dp0simulate_attacks.py" --target file --out "%~dp0simulated_logs.jsonl"
pause
