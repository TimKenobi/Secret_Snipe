#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Repairs the SecretSnipe Agent Windows Service by fixing path quoting issues.
    
.DESCRIPTION
    This script fixes the NSSM service configuration when paths contain spaces
    (like "C:\Program Files\SecretSnipe").
    
.EXAMPLE
    .\Repair-SecretSnipeService.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$SERVICE_NAME = "SecretSnipeAgent"
$InstallPath = "C:\Program Files\SecretSnipe"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " SecretSnipe Agent Service Repair Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if service exists
$service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Host "[ERROR] Service '$SERVICE_NAME' not found!" -ForegroundColor Red
    exit 1
}

# Stop the service first
Write-Host "[1/5] Stopping service..." -ForegroundColor Yellow
Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Find Python
Write-Host "[2/5] Locating Python..." -ForegroundColor Yellow
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    $pythonPath = (Get-Command python3 -ErrorAction SilentlyContinue).Source
}
if (-not $pythonPath) {
    Write-Host "[ERROR] Python not found in PATH!" -ForegroundColor Red
    exit 1
}
Write-Host "       Found Python: $pythonPath" -ForegroundColor Green

# Check if agent script exists
$agentScript = "$InstallPath\secretsnipe_agent.py"
if (-not (Test-Path $agentScript)) {
    Write-Host "[ERROR] Agent script not found at: $agentScript" -ForegroundColor Red
    Write-Host "       Run the installer to download it first." -ForegroundColor Yellow
    exit 1
}
Write-Host "       Found agent script: $agentScript" -ForegroundColor Green

# Find or download NSSM
Write-Host "[3/5] Checking NSSM..." -ForegroundColor Yellow
$nssmPath = "$InstallPath\nssm.exe"
if (-not (Test-Path $nssmPath)) {
    Write-Host "       NSSM not found, downloading..." -ForegroundColor Yellow
    try {
        $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
        $nssmZip = "$env:TEMP\nssm.zip"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
        Expand-Archive -Path $nssmZip -DestinationPath "$env:TEMP\nssm" -Force
        Copy-Item "$env:TEMP\nssm\nssm-2.24\win64\nssm.exe" -Destination $nssmPath
        Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\nssm" -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[ERROR] Could not download NSSM: $_" -ForegroundColor Red
        exit 1
    }
}
Write-Host "       NSSM ready: $nssmPath" -ForegroundColor Green

# Remove old service
Write-Host "[4/5] Removing old service configuration..." -ForegroundColor Yellow
& $nssmPath remove $SERVICE_NAME confirm 2>$null
Start-Sleep -Seconds 2

# Create service with proper quoting
Write-Host "[5/5] Creating service with properly quoted paths..." -ForegroundColor Yellow

# CRITICAL: Quote ALL paths that contain spaces
$quotedPythonPath = "`"$pythonPath`""
$quotedScriptPath = "`"$agentScript`""
$quotedInstallPath = "`"$InstallPath`""
$quotedStdout = "`"$InstallPath\logs\service_stdout.log`""
$quotedStderr = "`"$InstallPath\logs\service_stderr.log`""

Write-Host "       Python: $quotedPythonPath" -ForegroundColor Gray
Write-Host "       Script: $quotedScriptPath" -ForegroundColor Gray
Write-Host "       WorkDir: $quotedInstallPath" -ForegroundColor Gray

# Install service
& $nssmPath install $SERVICE_NAME $quotedPythonPath
& $nssmPath set $SERVICE_NAME AppParameters "$quotedScriptPath --service"
& $nssmPath set $SERVICE_NAME DisplayName "SecretSnipe Enterprise Agent"
& $nssmPath set $SERVICE_NAME Description "SecretSnipe distributed secret scanning agent"
& $nssmPath set $SERVICE_NAME AppDirectory $quotedInstallPath
& $nssmPath set $SERVICE_NAME AppStdout $quotedStdout
& $nssmPath set $SERVICE_NAME AppStderr $quotedStderr
& $nssmPath set $SERVICE_NAME AppRotateFiles 1
& $nssmPath set $SERVICE_NAME AppRotateBytes 10485760
& $nssmPath set $SERVICE_NAME AppExit Default Restart
& $nssmPath set $SERVICE_NAME AppRestartDelay 5000

Write-Host ""
Write-Host "Service reconfigured! Starting service..." -ForegroundColor Green

# Start the service
Start-Service -Name $SERVICE_NAME
Start-Sleep -Seconds 3

$service = Get-Service -Name $SERVICE_NAME
if ($service.Status -eq "Running") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " SUCCESS! Service is now running." -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Check status with: Get-Service $SERVICE_NAME" -ForegroundColor Cyan
    Write-Host "Check logs at: $InstallPath\logs\" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host " Service may have failed to start." -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Check error log:" -ForegroundColor Cyan
    Write-Host "  Get-Content `"$InstallPath\logs\service_stderr.log`" -Tail 20" -ForegroundColor White
    Write-Host ""
    Write-Host "Try running manually:" -ForegroundColor Cyan
    Write-Host "  cd `"$InstallPath`"" -ForegroundColor White
    Write-Host "  & `"$pythonPath`" secretsnipe_agent.py --service" -ForegroundColor White
}
