#!/bin/bash
# ==============================================================================
# SecretSnipe Agent Installer
# Installs the agent on a Linux host with systemd service
# 
# Usage: 
#   curl -fsSL https://your-server/install_agent.sh | sudo bash -s -- \
#       --manager-url https://manager.example.com:8443 \
#       --api-key YOUR_API_KEY
#
# Or download and run:
#   chmod +x install_agent.sh
#   sudo ./install_agent.sh --manager-url https://... --api-key ...
# ==============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="/opt/secretsnipe-agent"
SERVICE_USER="secretsnipe"
SERVICE_NAME="secretsnipe-agent"
PYTHON_MIN_VERSION="3.9"
AGENT_VERSION="1.0.0"

# Parse arguments
MANAGER_URL=""
API_KEY=""
SCAN_PATHS=""
SCANNERS="custom,trufflehog,gitleaks"

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "   SecretSnipe Agent Installer v${AGENT_VERSION}"
    echo "=================================================="
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  --manager-url URL     SecretSnipe Manager URL (e.g., https://manager:8443)"
    echo "  --api-key KEY         API key for agent authentication"
    echo ""
    echo "Optional:"
    echo "  --scan-paths PATHS    Comma-separated default scan paths"
    echo "  --scanners LIST       Comma-separated scanners (default: custom,trufflehog,gitleaks)"
    echo "  --install-dir DIR     Installation directory (default: /opt/secretsnipe-agent)"
    echo "  --user USER           Service user (default: secretsnipe)"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --manager-url https://manager.example.com:8443 --api-key abc123..."
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_system() {
    log_info "Checking system requirements..."
    
    # Check OS
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot determine OS. /etc/os-release not found."
        exit 1
    fi
    
    . /etc/os-release
    log_info "Detected OS: ${PRETTY_NAME}"
    
    # Check architecture
    ARCH=$(uname -m)
    log_info "Architecture: ${ARCH}"
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log_info "Python version: ${PYTHON_VERSION}"
        
        # Version check (basic)
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
            log_info "Python version is sufficient"
        else
            log_error "Python 3.9+ is required. Found: ${PYTHON_VERSION}"
            exit 1
        fi
    else
        log_error "Python 3 is not installed"
        log_info "Installing Python 3..."
        
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y python3 python3-pip python3-venv
        elif command -v yum &> /dev/null; then
            yum install -y python3 python3-pip
        elif command -v dnf &> /dev/null; then
            dnf install -y python3 python3-pip
        else
            log_error "Could not install Python. Please install manually."
            exit 1
        fi
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_warn "pip3 not found, installing..."
        python3 -m ensurepip --upgrade || true
    fi
}

create_user() {
    log_info "Creating service user: ${SERVICE_USER}"
    
    if id "${SERVICE_USER}" &>/dev/null; then
        log_info "User ${SERVICE_USER} already exists"
    else
        useradd --system --no-create-home --shell /bin/false "${SERVICE_USER}"
        log_info "Created user ${SERVICE_USER}"
    fi
}

install_agent() {
    log_info "Installing agent to ${INSTALL_DIR}..."
    
    # Create directory structure
    mkdir -p "${INSTALL_DIR}"/{bin,lib,config,logs}
    
    # Create virtual environment
    log_info "Creating Python virtual environment..."
    python3 -m venv "${INSTALL_DIR}/venv"
    
    # Activate venv and install dependencies
    source "${INSTALL_DIR}/venv/bin/activate"
    
    log_info "Installing Python dependencies..."
    pip install --upgrade pip
    pip install requests psutil pyyaml
    
    # Try to install optional scanners
    log_info "Installing optional scanner tools..."
    
    # TruffleHog
    if pip install trufflehog3 2>/dev/null || pip install truffleHog 2>/dev/null; then
        log_info "TruffleHog installed"
    else
        log_warn "Could not install TruffleHog via pip"
    fi
    
    # Gitleaks - try to download binary
    log_info "Checking for Gitleaks..."
    if ! command -v gitleaks &> /dev/null; then
        log_info "Downloading Gitleaks..."
        GITLEAKS_VERSION="8.18.0"
        GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz"
        
        if [[ "$ARCH" == "x86_64" ]]; then
            GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        elif [[ "$ARCH" == "aarch64" ]]; then
            GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"
        fi
        
        if curl -fsSL "${GITLEAKS_URL}" -o /tmp/gitleaks.tar.gz 2>/dev/null; then
            tar -xzf /tmp/gitleaks.tar.gz -C "${INSTALL_DIR}/bin" gitleaks
            chmod +x "${INSTALL_DIR}/bin/gitleaks"
            rm /tmp/gitleaks.tar.gz
            log_info "Gitleaks installed to ${INSTALL_DIR}/bin/"
        else
            log_warn "Could not download Gitleaks"
        fi
    else
        log_info "Gitleaks already available"
    fi
    
    deactivate
}

create_agent_script() {
    log_info "Creating agent script..."
    
    cat > "${INSTALL_DIR}/bin/agent_core.py" << 'AGENT_SCRIPT'
#!/usr/bin/env python3
"""
SecretSnipe Agent Core - Lightweight Secret Scanner Agent
This script runs on remote hosts and communicates with the central manager.
"""

import os
import sys
import json
import time
import socket
import hashlib
import logging
import platform
import threading
import subprocess
import re
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

import requests
import psutil

# ==================== Configuration ====================

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
        self.gitleaks_path = os.getenv("SECRETSNIPE_GITLEAKS_PATH", "")

# ==================== Logging ====================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/opt/secretsnipe-agent/logs/agent.log')
    ]
)
logger = logging.getLogger("secretsnipe-agent")

# ==================== Signatures ====================

SIGNATURES = [
    {"name": "AWS Access Key ID", "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "severity": "critical"},
    {"name": "AWS Secret Access Key", "pattern": r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "severity": "critical"},
    {"name": "GitHub Token", "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "severity": "high"},
    {"name": "GitHub OAuth Token", "pattern": r"gho_[A-Za-z0-9_]{36,}", "severity": "high"},
    {"name": "Generic API Key", "pattern": r"(?i)(api[_-]?key|apikey|api_secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", "severity": "medium"},
    {"name": "Generic Secret", "pattern": r"(?i)(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", "severity": "medium"},
    {"name": "Private Key Header", "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "Slack Token", "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "severity": "high"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z_-]{35}", "severity": "high"},
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "severity": "medium"},
]

SKIP_EXTENSIONS = {'.exe', '.dll', '.so', '.dylib', '.bin', '.pyc', '.pyo', '.class', 
                   '.jar', '.war', '.ear', '.zip', '.tar', '.gz', '.rar', '.7z',
                   '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
                   '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.doc', '.docx'}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', '.env',
             'vendor', 'dist', 'build', '.idea', '.vscode'}

# ==================== Agent Class ====================

class SecretSnipeAgent:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.agent_id = config.agent_id
        self.hostname = socket.gethostname()
        self.running = False
        self._heartbeat_thread = None
        self._poll_thread = None
        
        # Set log level
        logger.setLevel(getattr(logging, config.log_level.upper(), logging.INFO))
        
        # Compile patterns
        self.compiled_patterns = []
        for sig in SIGNATURES:
            try:
                self.compiled_patterns.append({
                    "name": sig["name"],
                    "pattern": re.compile(sig["pattern"]),
                    "severity": sig["severity"]
                })
            except re.error as e:
                logger.warning(f"Invalid pattern for {sig['name']}: {e}")
    
    def _get_headers(self) -> dict:
        return {
            "X-API-Key": self.config.api_key,
            "Content-Type": "application/json",
            "X-Agent-ID": self.agent_id
        }
    
    def _api_request(self, method: str, endpoint: str, data: dict = None) -> Optional[dict]:
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
            else:
                logger.error(f"API error {resp.status_code}: {resp.text[:200]}")
                return None
        except Exception as e:
            logger.error(f"API request failed: {e}")
            return None
    
    def register(self) -> bool:
        """Register agent with manager"""
        logger.info(f"Registering agent {self.hostname}...")
        
        capabilities = ["custom"]
        
        # Check for trufflehog
        try:
            subprocess.run(["trufflehog", "--version"], capture_output=True, timeout=5)
            capabilities.append("trufflehog")
        except:
            pass
        
        # Check for gitleaks
        gitleaks_cmd = self.config.gitleaks_path or "gitleaks"
        try:
            subprocess.run([gitleaks_cmd, "version"], capture_output=True, timeout=5)
            capabilities.append("gitleaks")
        except:
            pass
        
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
    
    def _get_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def send_heartbeat(self):
        """Send heartbeat to manager"""
        while self.running:
            try:
                data = {
                    "agent_id": self.agent_id,
                    "status": "online",
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('/').percent,
                    "uptime_seconds": int(time.time() - psutil.boot_time())
                }
                self._api_request("POST", "/agents/heartbeat", data)
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
            
            time.sleep(self.config.heartbeat_interval)
    
    def poll_for_jobs(self):
        """Poll for new jobs"""
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
    
    def _execute_job(self, job: dict):
        """Execute a scan job"""
        job_id = job.get("job_id")
        scan_paths = job.get("scan_paths", [])
        scanners = job.get("scanners", ["custom"])
        
        logger.info(f"Executing job {job_id} on {len(scan_paths)} paths")
        
        # Update status to running
        self._api_request("POST", "/jobs/status", {
            "job_id": job_id,
            "status": "running"
        })
        
        all_findings = []
        files_scanned = 0
        
        try:
            for scan_path in scan_paths:
                path = Path(scan_path)
                if not path.exists():
                    logger.warning(f"Path not found: {scan_path}")
                    continue
                
                # Custom scanner
                if "custom" in scanners:
                    findings, count = self._scan_path_custom(path)
                    all_findings.extend(findings)
                    files_scanned += count
                
                # TruffleHog
                if "trufflehog" in scanners:
                    findings = self._scan_path_trufflehog(path)
                    all_findings.extend(findings)
                
                # Gitleaks
                if "gitleaks" in scanners:
                    findings = self._scan_path_gitleaks(path)
                    all_findings.extend(findings)
            
            # Submit findings
            if all_findings:
                self._submit_findings(job_id, all_findings)
            
            # Mark complete
            self._api_request("POST", "/jobs/status", {
                "job_id": job_id,
                "status": "completed",
                "files_scanned": files_scanned,
                "findings_count": len(all_findings)
            })
            
            logger.info(f"Job {job_id} completed: {files_scanned} files, {len(all_findings)} findings")
            
        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}")
            self._api_request("POST", "/jobs/status", {
                "job_id": job_id,
                "status": "failed",
                "error_message": str(e)
            })
    
    def _scan_path_custom(self, path: Path) -> tuple:
        """Scan with custom regex patterns"""
        findings = []
        files_scanned = 0
        
        if path.is_file():
            files = [path]
        else:
            files = self._get_files(path)
        
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
                                "pattern_name": pattern_info["name"],
                                "severity": pattern_info["severity"],
                                "hostname": self.hostname
                            })
                            
            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")
        
        return findings, files_scanned
    
    def _get_files(self, directory: Path) -> list:
        """Get files to scan"""
        files = []
        try:
            for item in directory.rglob('*'):
                if item.is_file():
                    if item.suffix.lower() in SKIP_EXTENSIONS:
                        continue
                    if any(skip in item.parts for skip in SKIP_DIRS):
                        continue
                    files.append(item)
        except Exception as e:
            logger.error(f"Error walking {directory}: {e}")
        return files
    
    def _scan_path_trufflehog(self, path: Path) -> list:
        """Scan with TruffleHog"""
        findings = []
        try:
            cmd = ["trufflehog", "filesystem", str(path), "--json", "--no-update"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        findings.append({
                            "secret_type": data.get("DetectorName", "TruffleHog Finding"),
                            "secret_value": data.get("Raw", "")[:100],
                            "file_path": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", str(path)),
                            "line_number": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                            "scanner": "trufflehog",
                            "severity": "high",
                            "hostname": self.hostname
                        })
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"TruffleHog scan failed: {e}")
        return findings
    
    def _scan_path_gitleaks(self, path: Path) -> list:
        """Scan with Gitleaks"""
        findings = []
        gitleaks_cmd = self.config.gitleaks_path or "gitleaks"
        
        try:
            cmd = [gitleaks_cmd, "detect", "--source", str(path), "--report-format", "json", "--report-path", "/dev/stdout", "--no-git"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            try:
                data = json.loads(result.stdout) if result.stdout else []
                for item in data:
                    findings.append({
                        "secret_type": item.get("Description", "Gitleaks Finding"),
                        "secret_value": item.get("Secret", "")[:100],
                        "file_path": item.get("File", str(path)),
                        "line_number": item.get("StartLine", 0),
                        "scanner": "gitleaks",
                        "pattern_name": item.get("RuleID", ""),
                        "severity": "high",
                        "hostname": self.hostname
                    })
            except json.JSONDecodeError:
                pass
        except Exception as e:
            logger.error(f"Gitleaks scan failed: {e}")
        return findings
    
    def _submit_findings(self, job_id: str, findings: list):
        """Submit findings to manager"""
        logger.info(f"Submitting {len(findings)} findings for job {job_id}")
        
        # Batch submit
        batch_size = 100
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            self._api_request("POST", "/findings/submit", {
                "job_id": job_id,
                "agent_id": self.agent_id,
                "findings": batch
            })
    
    def start(self):
        """Start the agent"""
        logger.info("Starting SecretSnipe Agent...")
        
        if not self.config.manager_url or not self.config.api_key:
            logger.error("Manager URL and API key are required")
            return False
        
        if not self.register():
            logger.error("Failed to register with manager")
            return False
        
        self.running = True
        
        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(target=self.send_heartbeat, daemon=True)
        self._heartbeat_thread.start()
        
        # Start job polling thread
        self._poll_thread = threading.Thread(target=self.poll_for_jobs, daemon=True)
        self._poll_thread.start()
        
        logger.info("Agent started successfully")
        return True
    
    def stop(self):
        """Stop the agent"""
        logger.info("Stopping agent...")
        self.running = False
    
    def run_forever(self):
        """Run until interrupted"""
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
AGENT_SCRIPT
    
    chmod +x "${INSTALL_DIR}/bin/agent_core.py"
    log_info "Agent script created"
}

create_config() {
    log_info "Creating configuration..."
    
    cat > "${INSTALL_DIR}/config/agent.env" << EOF
# SecretSnipe Agent Configuration
# Generated: $(date)

# Manager Connection (REQUIRED)
SECRETSNIPE_MANAGER_URL=${MANAGER_URL}
SECRETSNIPE_API_KEY=${API_KEY}

# Agent Settings
SECRETSNIPE_AGENT_ID=
SECRETSNIPE_SCAN_PATHS=${SCAN_PATHS}
SECRETSNIPE_HEARTBEAT_INTERVAL=30
SECRETSNIPE_POLL_INTERVAL=10
SECRETSNIPE_LOG_LEVEL=INFO
SECRETSNIPE_MAX_FILE_SIZE=10485760

# External Tools
SECRETSNIPE_GITLEAKS_PATH=${INSTALL_DIR}/bin/gitleaks
EOF

    chmod 600 "${INSTALL_DIR}/config/agent.env"
    log_info "Configuration file created at ${INSTALL_DIR}/config/agent.env"
}

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SecretSnipe Secret Scanner Agent
Documentation=https://github.com/your-repo/secretsnipe
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/config/agent.env
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/bin/agent_core.py
Restart=always
RestartSec=10
TimeoutStopSec=30

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${INSTALL_DIR}/logs

# Resource limits
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service created"
}

set_permissions() {
    log_info "Setting permissions..."
    
    chown -R ${SERVICE_USER}:${SERVICE_USER} "${INSTALL_DIR}"
    chmod -R 750 "${INSTALL_DIR}"
    chmod 700 "${INSTALL_DIR}/config"
    chmod 600 "${INSTALL_DIR}/config/agent.env"
}

start_service() {
    log_info "Starting service..."
    
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    
    sleep 2
    
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        log_info "Service started successfully"
    else
        log_error "Service failed to start. Check: journalctl -u ${SERVICE_NAME}"
        exit 1
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}=================================================="
    echo "   Installation Complete!"
    echo "==================================================${NC}"
    echo ""
    echo "Installation Directory: ${INSTALL_DIR}"
    echo "Service Name:           ${SERVICE_NAME}"
    echo "Service User:           ${SERVICE_USER}"
    echo ""
    echo "Useful Commands:"
    echo "  Status:   systemctl status ${SERVICE_NAME}"
    echo "  Logs:     journalctl -u ${SERVICE_NAME} -f"
    echo "  Restart:  systemctl restart ${SERVICE_NAME}"
    echo "  Stop:     systemctl stop ${SERVICE_NAME}"
    echo ""
    echo "Configuration: ${INSTALL_DIR}/config/agent.env"
    echo ""
}

# ==================== Main ====================

main() {
    print_banner
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --manager-url)
                MANAGER_URL="$2"
                shift 2
                ;;
            --api-key)
                API_KEY="$2"
                shift 2
                ;;
            --scan-paths)
                SCAN_PATHS="$2"
                shift 2
                ;;
            --scanners)
                SCANNERS="$2"
                shift 2
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --user)
                SERVICE_USER="$2"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
    
    # Validate required arguments
    if [ -z "$MANAGER_URL" ] || [ -z "$API_KEY" ]; then
        log_error "Manager URL and API key are required"
        usage
    fi
    
    # Run installation
    check_root
    check_system
    create_user
    install_agent
    create_agent_script
    create_config
    set_permissions
    create_systemd_service
    start_service
    print_summary
}

main "$@"
