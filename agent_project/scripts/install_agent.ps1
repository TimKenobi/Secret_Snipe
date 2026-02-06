# SecretSnipe Agent Installer - Windows PowerShell Version
# Usage: .\install_agent.ps1 -ManagerUrl "https://manager:8443" -ApiKey "your_api_key"

param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$ScanPaths = "",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "C:\SecretSnipe-Agent"
)

$ErrorActionPreference = "Stop"

# Colors
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

Write-Host @"
==================================================
   SecretSnipe Agent Installer (Windows)
==================================================
"@ -ForegroundColor Cyan

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Err "This script must be run as Administrator"
    exit 1
}

# Check Python
Write-Info "Checking Python..."
try {
    $pythonVersion = python --version 2>&1
    Write-Info "Found: $pythonVersion"
} catch {
    Write-Err "Python is not installed. Please install Python 3.9+ from python.org"
    exit 1
}

# Create directories
Write-Info "Creating installation directory: $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\bin" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\config" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\logs" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\venv" | Out-Null

# Create virtual environment
Write-Info "Creating Python virtual environment..."
python -m venv "$InstallDir\venv"

# Activate and install dependencies
Write-Info "Installing dependencies..."
& "$InstallDir\venv\Scripts\pip.exe" install --upgrade pip
& "$InstallDir\venv\Scripts\pip.exe" install requests psutil pyyaml

# Try to install TruffleHog
Write-Info "Installing TruffleHog..."
try {
    & "$InstallDir\venv\Scripts\pip.exe" install trufflehog3
} catch {
    Write-Warn "Could not install TruffleHog"
}

# Download Gitleaks
Write-Info "Downloading Gitleaks..."
$gitleaksVersion = "8.18.0"
$gitleaksUrl = "https://github.com/gitleaks/gitleaks/releases/download/v$gitleaksVersion/gitleaks_${gitleaksVersion}_windows_x64.zip"
$gitleaksZip = "$env:TEMP\gitleaks.zip"

try {
    Invoke-WebRequest -Uri $gitleaksUrl -OutFile $gitleaksZip
    Expand-Archive -Path $gitleaksZip -DestinationPath "$InstallDir\bin" -Force
    Remove-Item $gitleaksZip -Force
    Write-Info "Gitleaks installed"
} catch {
    Write-Warn "Could not download Gitleaks: $_"
}

# Create agent script
Write-Info "Creating agent script..."
$agentScript = @'
#!/usr/bin/env python3
"""SecretSnipe Agent Core - Windows Version"""

import os
import sys
import json
import time
import socket
import logging
import platform
import threading
import subprocess
import re
from pathlib import Path
from datetime import datetime

import requests
import psutil

# Configuration
class AgentConfig:
    def __init__(self):
        self.manager_url = os.getenv("SECRETSNIPE_MANAGER_URL", "")
        self.api_key = os.getenv("SECRETSNIPE_API_KEY", "")
        self.agent_id = os.getenv("SECRETSNIPE_AGENT_ID", "")
        self.scan_paths = os.getenv("SECRETSNIPE_SCAN_PATHS", "").split(",") if os.getenv("SECRETSNIPE_SCAN_PATHS") else []
        self.heartbeat_interval = int(os.getenv("SECRETSNIPE_HEARTBEAT_INTERVAL", "30"))
        self.poll_interval = int(os.getenv("SECRETSNIPE_POLL_INTERVAL", "10"))
        self.log_level = os.getenv("SECRETSNIPE_LOG_LEVEL", "INFO")
        self.max_file_size = int(os.getenv("SECRETSNIPE_MAX_FILE_SIZE", str(10 * 1024 * 1024)))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(r'C:\SecretSnipe-Agent\logs\agent.log')
    ]
)
logger = logging.getLogger("secretsnipe-agent")

SIGNATURES = [
    {"name": "AWS Access Key ID", "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "severity": "critical"},
    {"name": "AWS Secret Access Key", "pattern": r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "severity": "critical"},
    {"name": "GitHub Token", "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "severity": "high"},
    {"name": "Generic API Key", "pattern": r"(?i)(api[_-]?key|apikey|api_secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", "severity": "medium"},
    {"name": "Generic Secret", "pattern": r"(?i)(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", "severity": "medium"},
    {"name": "Private Key Header", "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical"},
]

SKIP_EXTENSIONS = {'.exe', '.dll', '.so', '.bin', '.pyc', '.class', '.jar', '.zip', '.tar', '.gz',
                   '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.mp3', '.mp4', '.pdf'}
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', 'vendor', 'dist', 'build'}

class SecretSnipeAgent:
    def __init__(self, config):
        self.config = config
        self.agent_id = config.agent_id
        self.hostname = socket.gethostname()
        self.running = False
        self.compiled_patterns = []
        for sig in SIGNATURES:
            try:
                self.compiled_patterns.append({
                    "name": sig["name"],
                    "pattern": re.compile(sig["pattern"]),
                    "severity": sig["severity"]
                })
            except:
                pass
    
    def _get_headers(self):
        return {"X-API-Key": self.config.api_key, "Content-Type": "application/json", "X-Agent-ID": self.agent_id}
    
    def _api_request(self, method, endpoint, data=None):
        url = f"{self.config.manager_url.rstrip('/')}/api/v1{endpoint}"
        try:
            if method == "GET":
                resp = requests.get(url, headers=self._get_headers(), timeout=30)
            elif method == "POST":
                resp = requests.post(url, headers=self._get_headers(), json=data, timeout=30)
            else:
                return None
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.error(f"API request failed: {e}")
            return None
    
    def _get_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def register(self):
        logger.info(f"Registering agent {self.hostname}...")
        capabilities = ["custom"]
        
        data = {
            "hostname": self.hostname,
            "ip_address": self._get_ip(),
            "os_type": platform.system(),
            "os_version": platform.release(),
            "agent_version": "1.0.0",
            "capabilities": capabilities,
            "scan_paths": self.config.scan_paths
        }
        
        result = self._api_request("POST", "/agents/register", data)
        if result and result.get("success"):
            self.agent_id = result.get("data", {}).get("agent_id", self.agent_id)
            logger.info(f"Registered with agent_id: {self.agent_id}")
            return True
        return False
    
    def send_heartbeat(self):
        while self.running:
            try:
                data = {
                    "agent_id": self.agent_id,
                    "status": "online",
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent,
                    "uptime_seconds": int(time.time() - psutil.boot_time())
                }
                self._api_request("POST", "/agents/heartbeat", data)
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
            time.sleep(self.config.heartbeat_interval)
    
    def poll_for_jobs(self):
        while self.running:
            try:
                result = self._api_request("GET", f"/jobs/poll?agent_id={self.agent_id}")
                if result and result.get("success") and result.get("data"):
                    job = result["data"]
                    logger.info(f"Received job: {job.get('job_id')}")
                    self._execute_job(job)
            except Exception as e:
                logger.error(f"Job poll failed: {e}")
            time.sleep(self.config.poll_interval)
    
    def _execute_job(self, job):
        job_id = job.get("job_id")
        scan_paths = job.get("scan_paths", [])
        
        self._api_request("POST", "/jobs/status", {"job_id": job_id, "status": "running"})
        
        all_findings = []
        files_scanned = 0
        
        try:
            for scan_path in scan_paths:
                path = Path(scan_path)
                if not path.exists():
                    continue
                findings, count = self._scan_path_custom(path)
                all_findings.extend(findings)
                files_scanned += count
            
            if all_findings:
                self._submit_findings(job_id, all_findings)
            
            self._api_request("POST", "/jobs/status", {
                "job_id": job_id, "status": "completed",
                "files_scanned": files_scanned, "findings_count": len(all_findings)
            })
            logger.info(f"Job {job_id} completed: {files_scanned} files, {len(all_findings)} findings")
        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}")
            self._api_request("POST", "/jobs/status", {"job_id": job_id, "status": "failed", "error_message": str(e)})
    
    def _scan_path_custom(self, path):
        findings = []
        files_scanned = 0
        files = [path] if path.is_file() else self._get_files(path)
        
        for file_path in files:
            try:
                if file_path.stat().st_size > self.config.max_file_size:
                    continue
                files_scanned += 1
                content = file_path.read_text(errors='ignore')
                lines = content.split('\n')
                
                for pattern_info in self.compiled_patterns:
                    for line_num, line in enumerate(lines, 1):
                        for match in pattern_info["pattern"].finditer(line):
                            findings.append({
                                "secret_type": pattern_info["name"],
                                "secret_value": match.group()[:100],
                                "file_path": str(file_path),
                                "line_number": line_num,
                                "line_content": line[:500],
                                "scanner": "custom",
                                "severity": pattern_info["severity"],
                                "hostname": self.hostname
                            })
            except:
                pass
        return findings, files_scanned
    
    def _get_files(self, directory):
        files = []
        try:
            for item in directory.rglob('*'):
                if item.is_file():
                    if item.suffix.lower() in SKIP_EXTENSIONS:
                        continue
                    if any(skip in item.parts for skip in SKIP_DIRS):
                        continue
                    files.append(item)
        except:
            pass
        return files
    
    def _submit_findings(self, job_id, findings):
        logger.info(f"Submitting {len(findings)} findings for job {job_id}")
        batch_size = 100
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            self._api_request("POST", "/findings/submit", {
                "job_id": job_id, "agent_id": self.agent_id, "findings": batch
            })
    
    def start(self):
        logger.info("Starting SecretSnipe Agent...")
        if not self.config.manager_url or not self.config.api_key:
            logger.error("Manager URL and API key are required")
            return False
        if not self.register():
            logger.error("Failed to register with manager")
            return False
        
        self.running = True
        threading.Thread(target=self.send_heartbeat, daemon=True).start()
        threading.Thread(target=self.poll_for_jobs, daemon=True).start()
        logger.info("Agent started successfully")
        return True
    
    def stop(self):
        self.running = False
    
    def run_forever(self):
        if not self.start():
            return
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

if __name__ == "__main__":
    config = AgentConfig()
    agent = SecretSnipeAgent(config)
    agent.run_forever()
'@

$agentScript | Out-File -FilePath "$InstallDir\bin\agent_core.py" -Encoding UTF8

# Create config file
Write-Info "Creating configuration..."
$configContent = @"
# SecretSnipe Agent Configuration
# Generated: $(Get-Date)

SECRETSNIPE_MANAGER_URL=$ManagerUrl
SECRETSNIPE_API_KEY=$ApiKey
SECRETSNIPE_AGENT_ID=
SECRETSNIPE_SCAN_PATHS=$ScanPaths
SECRETSNIPE_HEARTBEAT_INTERVAL=30
SECRETSNIPE_POLL_INTERVAL=10
SECRETSNIPE_LOG_LEVEL=INFO
SECRETSNIPE_MAX_FILE_SIZE=10485760
"@

$configContent | Out-File -FilePath "$InstallDir\config\agent.env" -Encoding UTF8

# Create batch script for running
$batchScript = @"
@echo off
cd /d $InstallDir
set /p vars=<config\agent.env
for /f "tokens=1,2 delims==" %%a in (config\agent.env) do (
    set %%a=%%b
)
venv\Scripts\python.exe bin\agent_core.py
"@

$batchScript | Out-File -FilePath "$InstallDir\run_agent.bat" -Encoding ASCII

# Create Windows Service using NSSM or sc
Write-Info "Creating Windows service..."

# Try to create a Task Scheduler task (simpler than NSSM for now)
$action = New-ScheduledTaskAction -Execute "$InstallDir\venv\Scripts\python.exe" -Argument "$InstallDir\bin\agent_core.py" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

try {
    Register-ScheduledTask -TaskName "SecretSnipeAgent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
    
    # Set environment variables for the task
    $envVars = @{
        "SECRETSNIPE_MANAGER_URL" = $ManagerUrl
        "SECRETSNIPE_API_KEY" = $ApiKey
        "SECRETSNIPE_SCAN_PATHS" = $ScanPaths
    }
    
    foreach ($var in $envVars.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($var.Key, $var.Value, "Machine")
    }
    
    Write-Info "Windows scheduled task created"
    
    # Start the task
    Start-ScheduledTask -TaskName "SecretSnipeAgent"
    Write-Info "Agent started"
    
} catch {
    Write-Warn "Could not create scheduled task: $_"
    Write-Info "You can run the agent manually using: $InstallDir\run_agent.bat"
}

Write-Host @"

==================================================
   Installation Complete!
==================================================

Installation Directory: $InstallDir
Configuration File:     $InstallDir\config\agent.env

Useful Commands:
  Start:   Start-ScheduledTask -TaskName 'SecretSnipeAgent'
  Stop:    Stop-ScheduledTask -TaskName 'SecretSnipeAgent'
  Status:  Get-ScheduledTask -TaskName 'SecretSnipeAgent'
  Logs:    Get-Content $InstallDir\logs\agent.log -Tail 50

"@ -ForegroundColor Green
