# ThreatWatch demo launcher
# -------------------------
# Starts ThreatWatch locally for a live presentation:
#   * generates a cryptographically secure, EPHEMERAL console token
#     (kept only in this process's environment - never written to a tracked
#     file, never committed, never displayed in the UI)
#   * uses the mock AI provider (fully offline, deterministic)
#   * uses a fresh local demo database in %TEMP%
#   * opens the dashboard in your browser
#
# Usage:  .\demo.ps1            (from the repository root)
# Stop:   close the server window, or:  Stop-Process -Id <printed PID>

$ErrorActionPreference = 'Stop'

$port = 5000

# 1. Ephemeral secure token (.NET cryptographic RNG, 32 hex chars).
$bytes = New-Object byte[] 16
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$token = 'tw-demo-' + (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')

# 2. Local demo database (per run, in %TEMP%; safe to delete any time).
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dbFile = Join-Path $env:TEMP "threatwatch-demo-$stamp.sqlite"
$logFile = Join-Path $env:TEMP "threatwatch-demo-$stamp.log"

# 3. Environment for the server process (children inherit these).
$env:DB_FILE = $dbFile
$env:INGEST_TOKEN = $token
$env:AI_LLM_PROVIDER = 'mock'
$env:PORT = "$port"

Write-Host ''
Write-Host '=== ThreatWatch Demo ===' -ForegroundColor Cyan
Write-Host 'Synthetic security validation environment - no real attacks,'
Write-Host 'no real network traffic, all SOAR actions are dry-run.'
Write-Host ''
Write-Host ("Database : " + $dbFile)
Write-Host ("AI       : mock provider (offline, advisory)")
Write-Host ("Token    : stored in process environment only (not on disk)")

# 4. Start the server (independent process, survives this launcher).
$server = Start-Process -FilePath 'uv' `
  -ArgumentList 'run', 'python', 'app.py' `
  -WorkingDirectory $PSScriptRoot `
  -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err" `
  -PassThru

# 5. Wait for the dashboard to answer.
$url = "http://127.0.0.1:$port/"
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Milliseconds 500
  try {
    $null = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
    $ready = $true
    break
  } catch { }
}

Write-Host ''
if ($ready) {
  Write-Host ("Dashboard: " + $url) -ForegroundColor Green
  Write-Host ("Console token (paste into the dashboard token field):")
  Write-Host ("  " + $token) -ForegroundColor Yellow
  Write-Host ''
  Write-Host ("Server PID: " + $server.Id + "  (stop: Stop-Process -Id " + $server.Id + ")")
  Write-Host ("Log: " + $logFile)
  Write-Host ''
  Write-Host 'Opening the dashboard ...'
  Start-Process $url
} else {
  Write-Host 'Server did not answer within 15 s - check the log:' -ForegroundColor Red
  Write-Host ("  " + $logFile + ".err")
}
