<#
.SYNOPSIS
  Launch OptimizeMe in hot-reload dev mode (or run checks / release build).
  Watches both React/TypeScript (Vite HMR) and Rust (Tauri auto-rebuild).
#>
param(
    [switch]$Check,
    [switch]$Build,
    [switch]$CleanTarget
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host "`n=== OptimizeMe Runner ===" -ForegroundColor Cyan

# Check prerequisites
foreach ($cmd in @("node", "npm", "cargo")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "Missing required tool '$cmd' in PATH."
        exit 1
    }
}

# Optional clean of Rust target directory to reclaim build cache space
if ($CleanTarget) {
    Write-Host "[1/3] Cleaning Rust target artifacts..." -ForegroundColor Yellow
    cargo clean --manifest-path "$ProjectRoot\src-tauri\Cargo.toml"
}

# Warn if drive has < 2 GB free
$driveLetter = (Get-Location).Drive.Name
$drive = Get-PSDrive $driveLetter -ErrorAction SilentlyContinue
if ($drive) {
    $freeGB = [math]::Round($drive.Free / 1GB, 2)
    Write-Host "Drive ${driveLetter}: free space: $freeGB GB" -ForegroundColor DarkGray
    if ($freeGB -lt 2.0) {
        Write-Warning "Low disk space (${freeGB} GB free). If Cargo linking fails, run .\run-dev.ps1 -CleanTarget"
    }
}

# Ensure node_modules exists
if (-not (Test-Path "$ProjectRoot\node_modules")) {
    Write-Host "Installing npm dependencies..." -ForegroundColor Yellow
    npm install
}

if ($Check) {
    Write-Host "`nRunning TypeScript check..." -ForegroundColor Cyan
    npx tsc --noEmit
    Write-Host "Running Rust library tests..." -ForegroundColor Cyan
    cargo test --manifest-path "$ProjectRoot\src-tauri\Cargo.toml" --lib
    Write-Host "`nAll checks passed!" -ForegroundColor Green
    exit 0
}

if ($Build) {
    Write-Host "`nBuilding production bundle & installer..." -ForegroundColor Cyan
    npm run tauri build
    exit $LASTEXITCODE
}

# Clear stale listener on Vite port 1420 if an old dev session is still hanging
$port1420 = Get-NetTCPConnection -LocalPort 1420 -State Listen -ErrorAction SilentlyContinue
if ($port1420) {
    $pids = $port1420 | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($p in $pids) {
        if ($p -and $p -ne 0) {
            Write-Host "Stopping stale process on port 1420 (PID $p)..." -ForegroundColor Yellow
            Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 300
}

Write-Host "Starting Tauri dev mode (Vite HMR + Rust auto-reload)..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop.`n" -ForegroundColor DarkGray
npm run tauri dev
