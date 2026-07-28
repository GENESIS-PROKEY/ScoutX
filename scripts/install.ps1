# ================================================================
# ScoutX Windows Installer (PowerShell)
# Usage: irm https://raw.githubusercontent.com/lo/ScoutX/main/scripts/install.ps1 | iex
# ================================================================

Write-Host ""
Write-Host "  ScoutX Installer v2.0" -ForegroundColor Cyan
Write-Host "  =====================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "[1/3] Checking Python..." -ForegroundColor Blue
try {
    $pyVer = python --version 2>&1
    Write-Host "  $pyVer" -ForegroundColor Green
} catch {
    Write-Host "  Python 3.10+ required. Install from https://python.org" -ForegroundColor Red
    exit 1
}

# Install ScoutX
Write-Host ""
Write-Host "[2/3] Installing ScoutX..." -ForegroundColor Blue
if (Test-Path "pyproject.toml") {
    pip install -e ".[full]" 2>$null
    if ($LASTEXITCODE -ne 0) { pip install -e . }
    Write-Host "  ScoutX installed (editable mode)" -ForegroundColor Green
} else {
    pip install scoutx 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  PyPI not available. Clone repo first." -ForegroundColor Yellow
        exit 1
    }
}

# Verify
Write-Host ""
Write-Host "[3/3] Verifying..." -ForegroundColor Blue
try {
    scoutx --version
    Write-Host "  ScoutX is ready!" -ForegroundColor Green
} catch {
    Write-Host "  Run: scoutx --help" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "  Run a scan:     scoutx scan example.com" -ForegroundColor Cyan
Write-Host "  Check tools:    scoutx doctor" -ForegroundColor Cyan
Write-Host "  Install tools:  scoutx doctor --install all" -ForegroundColor Cyan
Write-Host ""
