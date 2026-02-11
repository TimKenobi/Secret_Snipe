# SecretSnipe Agent Update Script
# Run this as Administrator on the Windows machine

$ErrorActionPreference = "Stop"
$AgentPath = "C:\Program Files\SecretSnipe"
$ServiceName = "SecretSnipe Agent"
$ServerUrl = "http://10.150.110.24:8443"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SecretSnipe Agent Update Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

# Stop the service
Write-Host "[1/4] Stopping SecretSnipe Agent service..." -ForegroundColor Yellow
try {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
        Write-Host "      Service stopped." -ForegroundColor Green
    } else {
        Write-Host "      Service not found (will continue anyway)." -ForegroundColor Yellow
    }
} catch {
    Write-Host "      Warning: Could not stop service: $_" -ForegroundColor Yellow
}

# Backup old agent
Write-Host "[2/4] Backing up current agent..." -ForegroundColor Yellow
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = "$AgentPath\backup_$timestamp"
if (Test-Path "$AgentPath\secretsnipe_enterprise_agent.py") {
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    Copy-Item "$AgentPath\secretsnipe_enterprise_agent.py" "$backupPath\" -Force
    Write-Host "      Backed up to $backupPath" -ForegroundColor Green
} else {
    Write-Host "      No existing agent file found." -ForegroundColor Yellow
}

# Download new agent
Write-Host "[3/4] Downloading new agent from server..." -ForegroundColor Yellow
$agentUrl = "$ServerUrl/api/v1/agent/download"
$destFile = "$AgentPath\secretsnipe_enterprise_agent.py"

try {
    # Download from API endpoint
    Invoke-WebRequest -Uri $agentUrl -OutFile $destFile -UseBasicParsing -ErrorAction Stop
    Write-Host "      Downloaded successfully." -ForegroundColor Green
} catch {
    Write-Host "      ERROR: Could not download agent file: $_" -ForegroundColor Red
    Write-Host "      Please manually copy secretsnipe_enterprise_agent.py to $AgentPath" -ForegroundColor Red
    exit 1
}

# Verify file was downloaded
if (-NOT (Test-Path $destFile)) {
    Write-Host "      ERROR: Agent file not found after download!" -ForegroundColor Red
    exit 1
}

$fileSize = (Get-Item $destFile).Length
Write-Host "      File size: $fileSize bytes" -ForegroundColor Green

# Start the service
Write-Host "[4/4] Starting SecretSnipe Agent service..." -ForegroundColor Yellow
try {
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    $service = Get-Service -Name $ServiceName
    if ($service.Status -eq "Running") {
        Write-Host "      Service started successfully!" -ForegroundColor Green
    } else {
        Write-Host "      Warning: Service status is $($service.Status)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "      ERROR: Could not start service: $_" -ForegroundColor Red
    Write-Host "      Try starting manually: Start-Service '$ServiceName'" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Update Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Check agent logs: Get-Content '$AgentPath\logs\agent.log' -Tail 50" -ForegroundColor White
Write-Host "2. Create a new scan job from the V2 Dashboard" -ForegroundColor White
Write-Host "3. You should now see findings being reported" -ForegroundColor White
Write-Host ""
