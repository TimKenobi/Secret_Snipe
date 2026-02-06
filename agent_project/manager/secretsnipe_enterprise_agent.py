#!/usr/bin/env python3
"""
SecretSnipe Enterprise Agent
Windows/Linux agent for distributed secret scanning

This agent connects to the SecretSnipe Agent Manager to:
- Register itself with the fleet
- Receive scan jobs
- Execute scans using configured tools (Custom regex, Gitleaks, Trufflehog)
- Report results back to the manager
- Send heartbeats and status updates
"""

import os
import sys
import json
import time
import socket
import hashlib
import logging
import argparse
import threading
import platform
import subprocess
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party imports
try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("ERROR: 'psutil' package required. Install with: pip install psutil")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class AgentConfig:
    """Agent configuration"""
    manager_url: str
    api_key: str
    machine_fingerprint: str = ""
    log_level: str = "INFO"
    heartbeat_interval: int = 30
    job_poll_interval: int = 10
    max_cpu_percent: int = 50
    max_memory_mb: int = 512
    scan_timeout: int = 3600  # 1 hour max per scan
    verify_ssl: bool = True
    
    # Scanner settings
    enable_custom: bool = True
    enable_gitleaks: bool = False
    enable_trufflehog: bool = False
    gitleaks_path: str = ""
    
    # File watcher
    enable_file_watcher: bool = False
    watch_paths: List[str] = None
    
    def __post_init__(self):
        if self.watch_paths is None:
            self.watch_paths = []
        if not self.machine_fingerprint:
            self.machine_fingerprint = self._generate_fingerprint()
    
    def _generate_fingerprint(self) -> str:
        """Generate unique machine fingerprint"""
        hostname = socket.gethostname()
        try:
            # Get primary IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except:
            ip = "127.0.0.1"
        
        # Get MAC address
        mac = "unknown"
        try:
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 48, 8)])
        except:
            pass
        
        # Create fingerprint hash
        data = f"{hostname}|{ip}|{mac}|{platform.system()}|{platform.machine()}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(config: AgentConfig, log_dir: str = None):
    """Configure logging"""
    if log_dir is None:
        if platform.system() == "Windows":
            log_dir = r"C:\Program Files\SecretSnipe\logs"
        else:
            log_dir = "/var/log/secretsnipe"
    
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "agent.log")
    
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("SecretSnipeAgent")


# Remote log buffer for sending logs to manager API
_remote_log_buffer = []
_remote_log_buffer_max = 50  # Flush every 50 logs


class RemoteLogHandler(logging.Handler):
    """Custom logging handler that buffers logs for remote submission"""
    
    def emit(self, record):
        global _remote_log_buffer
        try:
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "message": record.getMessage(),
                "context": {
                    "module": record.module,
                    "funcName": record.funcName,
                    "lineno": record.lineno
                }
            }
            _remote_log_buffer.append(log_entry)
        except Exception:
            pass  # Never fail logging


# ============================================================================
# SIGNATURE PATTERNS (Built-in)
# ============================================================================

DEFAULT_SIGNATURES = [
    {
        "name": "AWS Access Key",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "CRITICAL"
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "severity": "CRITICAL"
    },
    {
        "name": "GitHub Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "severity": "CRITICAL"
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(?:api[_\-]?key|apikey|api_secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,64})['\"]?",
        "severity": "HIGH"
    },
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "CRITICAL"
    },
    {
        "name": "Password in Config",
        "pattern": r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
        "severity": "HIGH"
    },
    {
        "name": "Database Connection String",
        "pattern": r"(?i)(?:mysql|postgresql|mongodb|redis|mssql)://[^\s]+:[^\s]+@[^\s]+",
        "severity": "CRITICAL"
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "severity": "HIGH"
    },
    {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "severity": "HIGH"
    },
    {
        "name": "Azure Storage Key",
        "pattern": r"(?i)(?:accountkey|storagekey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{88})",
        "severity": "CRITICAL"
    }
]


# ============================================================================
# SCANNER IMPLEMENTATIONS
# ============================================================================

class BaseScanner:
    """Base class for scanners"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.name = "base"
    
    def scan(self, target_path: str, options: Dict = None) -> List[Dict]:
        """Scan a path and return findings"""
        raise NotImplementedError


class CustomRegexScanner(BaseScanner):
    """Custom regex-based scanner"""
    
    def __init__(self, logger: logging.Logger, signatures: List[Dict] = None):
        super().__init__(logger)
        self.name = "custom"
        self.signatures = signatures or DEFAULT_SIGNATURES
        self._compiled_patterns = []
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance"""
        for sig in self.signatures:
            try:
                compiled = re.compile(sig["pattern"], re.IGNORECASE | re.MULTILINE)
                self._compiled_patterns.append({
                    "name": sig["name"],
                    "pattern": compiled,
                    "severity": sig.get("severity", "MEDIUM")
                })
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern for {sig['name']}: {e}")
    
    def scan(self, target_path: str, options: Dict = None) -> List[Dict]:
        """Scan files for secrets using regex patterns"""
        findings = []
        options = options or {}
        
        target = Path(target_path)
        if not target.exists():
            self.logger.error(f"Target path does not exist: {target_path}")
            return findings
        
        # Get files to scan
        if target.is_file():
            files = [target]
        else:
            files = self._get_files(target, options)
        
        self.logger.info(f"Scanning {len(files)} files in {target_path}")
        
        for file_path in files:
            try:
                file_findings = self._scan_file(file_path)
                findings.extend(file_findings)
            except Exception as e:
                self.logger.warning(f"Error scanning {file_path}: {e}")
        
        return findings
    
    def _get_files(self, directory: Path, options: Dict) -> List[Path]:
        """Get list of files to scan"""
        files = []
        exclude_patterns = options.get("exclude_patterns", [
            "*.pyc", "*.pyo", "*.class", "*.o", "*.a", "*.so", "*.dll", "*.exe",
            "*.zip", "*.tar", "*.gz", "*.rar", "*.7z",
            "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
            "*.mp3", "*.mp4", "*.avi", "*.mov",
            "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx",
            "node_modules/*", ".git/*", "__pycache__/*", "*.min.js", "*.min.css"
        ])
        
        max_file_size = options.get("max_file_size", 10 * 1024 * 1024)  # 10MB default
        
        for root, dirs, filenames in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(
                Path(root) / d == Path(directory) / p.rstrip('/*') 
                for p in exclude_patterns if p.endswith('/*')
            )]
            
            for filename in filenames:
                file_path = Path(root) / filename
                
                # Check exclusions
                if any(file_path.match(p) for p in exclude_patterns):
                    continue
                
                # Check file size
                try:
                    if file_path.stat().st_size > max_file_size:
                        continue
                except:
                    continue
                
                files.append(file_path)
        
        return files
    
    def _scan_file(self, file_path: Path) -> List[Dict]:
        """Scan a single file for secrets"""
        findings = []
        
        try:
            # Try to read as text
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except:
            return findings
        
        lines = content.split('\n')
        
        for pattern_info in self._compiled_patterns:
            for match in pattern_info["pattern"].finditer(content):
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                # Get matched value (first group or full match)
                matched = match.group(1) if match.groups() else match.group(0)
                
                # Mask the secret
                if len(matched) > 8:
                    masked = matched[:4] + '*' * (len(matched) - 8) + matched[-4:]
                else:
                    masked = '*' * len(matched)
                
                findings.append({
                    "file": str(file_path),
                    "line": line_num,
                    "rule": pattern_info["name"],
                    "severity": pattern_info["severity"],
                    "match": masked,
                    "line_content": line_content[:200],  # Truncate long lines
                    "scanner": self.name,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        return findings


class GitleaksScanner(BaseScanner):
    """Gitleaks-based scanner"""
    
    def __init__(self, logger: logging.Logger, gitleaks_path: str = None):
        super().__init__(logger)
        self.name = "gitleaks"
        self.gitleaks_path = gitleaks_path or self._find_gitleaks()
    
    def _find_gitleaks(self) -> str:
        """Find gitleaks executable"""
        # Check common locations
        paths = ["gitleaks", "gitleaks.exe"]
        if platform.system() == "Windows":
            paths.extend([
                r"C:\Program Files\SecretSnipe\scanners\gitleaks.exe",
                r"C:\Program Files\gitleaks\gitleaks.exe"
            ])
        else:
            paths.extend([
                "/usr/local/bin/gitleaks",
                "/usr/bin/gitleaks",
                "/opt/gitleaks/gitleaks"
            ])
        
        for path in paths:
            if os.path.isfile(path):
                return path
            # Check PATH
            import shutil
            found = shutil.which(path)
            if found:
                return found
        
        return None
    
    def scan(self, target_path: str, options: Dict = None) -> List[Dict]:
        """Run gitleaks scan"""
        if not self.gitleaks_path:
            self.logger.warning("Gitleaks not found, skipping scan")
            return []
        
        findings = []
        options = options or {}
        
        try:
            # Run gitleaks
            output_file = os.path.join(os.environ.get('TEMP', '/tmp'), 'gitleaks_output.json')
            cmd = [
                self.gitleaks_path,
                "detect",
                "--source", target_path,
                "--report-format", "json",
                "--report-path", output_file,
                "--no-git"  # Scan files directly, not git history
            ]
            
            self.logger.info(f"Running gitleaks: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=options.get("timeout", 3600))
            
            # Parse output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    gitleaks_findings = json.load(f)
                
                for finding in gitleaks_findings:
                    findings.append({
                        "file": finding.get("File", ""),
                        "line": finding.get("StartLine", 0),
                        "rule": finding.get("RuleID", "unknown"),
                        "severity": self._map_severity(finding.get("Tags", [])),
                        "match": finding.get("Match", "")[:50] + "..." if len(finding.get("Match", "")) > 50 else finding.get("Match", ""),
                        "line_content": finding.get("Line", "")[:200],
                        "scanner": self.name,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
                os.remove(output_file)
        
        except subprocess.TimeoutExpired:
            self.logger.error("Gitleaks scan timed out")
        except Exception as e:
            self.logger.error(f"Gitleaks scan error: {e}")
        
        return findings
    
    def _map_severity(self, tags: List[str]) -> str:
        """Map gitleaks tags to severity"""
        if "critical" in [t.lower() for t in tags]:
            return "CRITICAL"
        elif "high" in [t.lower() for t in tags]:
            return "HIGH"
        elif "medium" in [t.lower() for t in tags]:
            return "MEDIUM"
        return "LOW"


class TrufflehogScanner(BaseScanner):
    """Trufflehog-based scanner"""
    
    def __init__(self, logger: logging.Logger):
        super().__init__(logger)
        self.name = "trufflehog"
    
    def scan(self, target_path: str, options: Dict = None) -> List[Dict]:
        """Run trufflehog scan"""
        findings = []
        options = options or {}
        
        try:
            # Run trufflehog via Python
            cmd = [
                sys.executable, "-m", "trufflehog",
                "--json",
                "--max_depth", "1000",
                "filesystem", target_path
            ]
            
            self.logger.info(f"Running trufflehog on {target_path}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=options.get("timeout", 3600))
            
            # Parse JSON output (one JSON object per line)
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    findings.append({
                        "file": finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                        "line": finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                        "rule": finding.get("DetectorName", "unknown"),
                        "severity": "HIGH" if finding.get("Verified", False) else "MEDIUM",
                        "match": finding.get("Raw", "")[:50] + "..." if len(finding.get("Raw", "")) > 50 else finding.get("Raw", ""),
                        "line_content": "",
                        "scanner": self.name,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                except json.JSONDecodeError:
                    pass
        
        except subprocess.TimeoutExpired:
            self.logger.error("Trufflehog scan timed out")
        except Exception as e:
            self.logger.error(f"Trufflehog scan error: {e}")
        
        return findings


# ============================================================================
# AGENT MANAGER CLIENT
# ============================================================================

class AgentManagerClient:
    """Client for communicating with the Agent Manager"""
    
    def __init__(self, config: AgentConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": config.api_key,
            "X-Agent-Fingerprint": config.machine_fingerprint,
            "Content-Type": "application/json"
        })
        self.session.verify = config.verify_ssl
    
    def _url(self, endpoint: str) -> str:
        """Build full URL"""
        base = self.config.manager_url.rstrip('/')
        return f"{base}/api/v1{endpoint}"
    
    def register(self) -> Dict:
        """Register agent with manager"""
        # Build capabilities list
        capabilities = []
        if self.config.enable_custom:
            capabilities.append("custom_scanner")
        if self.config.enable_gitleaks:
            capabilities.append("gitleaks")
        if self.config.enable_trufflehog:
            capabilities.append("trufflehog")
        if self.config.enable_file_watcher:
            capabilities.append("file_watcher")
        
        data = {
            "hostname": socket.gethostname(),
            "ip_address": self._get_ip(),
            "os_type": platform.system(),
            "os_version": platform.version(),
            "agent_version": "2.0.0",
            "capabilities": capabilities,
            "scan_paths": [],
            "tags": [],
            "metadata": {
                "python_version": platform.python_version(),
                "machine_fingerprint": self.config.machine_fingerprint
            }
        }
        
        try:
            resp = self.session.post(self._url("/agents/register"), json=data, timeout=30)
            resp.raise_for_status()
            result = resp.json()
            # Store the agent_id for heartbeats
            self.agent_id = result.get("data", {}).get("agent_id", self.config.machine_fingerprint)
            return result
        except Exception as e:
            self.logger.error(f"Registration failed: {e}")
            raise
    
    def heartbeat(self, status: str = "idle", current_job: str = None) -> Dict:
        """Send heartbeat to manager"""
        stats = self._get_system_stats()
        data = {
            "agent_id": getattr(self, 'agent_id', self.config.machine_fingerprint),
            "status": status,
            "current_job_id": current_job,
            "cpu_percent": stats.get("cpu_percent", 0),
            "memory_percent": stats.get("memory_percent", 0),
            "disk_percent": stats.get("disk_percent", 0),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            resp = self.session.post(self._url("/agents/heartbeat"), json=data, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            self.logger.warning(f"Heartbeat failed: {e}")
            return {}
    
    def get_pending_jobs(self) -> List[Dict]:
        """Get pending scan jobs for this agent"""
        try:
            # Use /jobs/poll endpoint with agent_id parameter
            agent_id = getattr(self, 'agent_id', self.config.machine_fingerprint)
            resp = self.session.get(self._url(f"/jobs/poll?agent_id={agent_id}"), timeout=30)
            resp.raise_for_status()
            result = resp.json()
            # The API returns a single job in data, wrap in list if present
            job = result.get("data")
            if job:
                return [job]
            return []
        except Exception as e:
            self.logger.warning(f"Failed to get jobs: {e}")
            return []
    
    def claim_job(self, job_id: str) -> bool:
        """Claim a job for processing"""
        try:
            resp = self.session.post(self._url(f"/jobs/{job_id}/claim"), timeout=10)
            resp.raise_for_status()
            return True
        except Exception as e:
            self.logger.warning(f"Failed to claim job {job_id}: {e}")
            return False
    
    def submit_results(self, job_id: str, findings: List[Dict], status: str = "completed") -> bool:
        """Submit scan results"""
        data = {
            "status": status,
            "findings": findings,
            "findings_count": len(findings),
            "completed_at": datetime.utcnow().isoformat()
        }
        
        try:
            resp = self.session.post(self._url(f"/jobs/{job_id}/results"), json=data, timeout=60)
            resp.raise_for_status()
            return True
        except Exception as e:
            self.logger.error(f"Failed to submit results for job {job_id}: {e}")
            return False
    
    def report_error(self, job_id: str, error: str) -> bool:
        """Report job error"""
        data = {
            "status": "failed",
            "error": error,
            "failed_at": datetime.utcnow().isoformat()
        }
        
        try:
            resp = self.session.post(self._url(f"/jobs/{job_id}/results"), json=data, timeout=30)
            resp.raise_for_status()
            return True
        except:
            return False
    
    def _get_ip(self) -> str:
        """Get primary IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _get_system_stats(self) -> Dict:
        """Get current system statistics"""
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent if platform.system() != "Windows" else psutil.disk_usage('C:\\').percent
        }
    
    def get_pending_commands(self) -> List[Dict]:
        """Get pending commands for this agent"""
        try:
            agent_id = getattr(self, 'agent_id', self.config.machine_fingerprint)
            resp = self.session.get(self._url(f"/agents/{agent_id}/commands"), timeout=10)
            resp.raise_for_status()
            result = resp.json()
            return result.get("data", [])
        except Exception as e:
            self.logger.debug(f"Failed to get commands: {e}")
            return []
    
    def complete_command(self, command_id: str, result: Dict = None) -> bool:
        """Report command completion to the server"""
        try:
            agent_id = getattr(self, 'agent_id', self.config.machine_fingerprint)
            resp = self.session.post(
                self._url(f"/agents/{agent_id}/commands/{command_id}/complete"),
                json={"result": result or {}},
                timeout=10
            )
            resp.raise_for_status()
            return True
        except Exception as e:
            self.logger.warning(f"Failed to report command completion: {e}")
            return False
    
    def flush_logs(self) -> bool:
        """Send buffered logs to the manager API"""
        global _remote_log_buffer
        if not hasattr(self, 'agent_id') or not _remote_log_buffer:
            return True
        
        # Grab buffer and reset
        logs_to_send = _remote_log_buffer[:50]  # Send max 50 at a time
        _remote_log_buffer = _remote_log_buffer[50:]
        
        try:
            resp = self.session.post(
                self._url(f"/agents/{self.agent_id}/logs"),
                json={"logs": logs_to_send},
                timeout=10
            )
            resp.raise_for_status()
            return True
        except Exception as e:
            # Put logs back if send failed
            _remote_log_buffer = logs_to_send + _remote_log_buffer
            self.logger.debug(f"Log flush failed: {e}")
            return False


# ============================================================================
# MAIN AGENT CLASS
# ============================================================================

class SecretSnipeEnterpriseAgent:
    """Main agent class"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = setup_logging(config)
        self.client = AgentManagerClient(config, self.logger)
        
        # Add remote log handler for server-side log collection
        remote_handler = RemoteLogHandler()
        remote_handler.setLevel(logging.INFO)
        self.logger.addHandler(remote_handler)
        
        # Initialize scanners
        self.scanners = {}
        if config.enable_custom:
            self.scanners["custom"] = CustomRegexScanner(self.logger)
        if config.enable_gitleaks:
            self.scanners["gitleaks"] = GitleaksScanner(self.logger, config.gitleaks_path)
        if config.enable_trufflehog:
            self.scanners["trufflehog"] = TrufflehogScanner(self.logger)
        
        self.running = False
        self.current_job = None
        self._heartbeat_thread = None
    
    def start(self):
        """Start the agent"""
        self.logger.info("=" * 60)
        self.logger.info("SecretSnipe Enterprise Agent Starting")
        self.logger.info(f"Machine Fingerprint: {self.config.machine_fingerprint}")
        self.logger.info(f"Manager URL: {self.config.manager_url}")
        self.logger.info(f"Scanners: {list(self.scanners.keys())}")
        self.logger.info("=" * 60)
        
        # Register with manager
        try:
            result = self.client.register()
            self.logger.info(f"Registered with manager: {result.get('message', 'OK')}")
        except Exception as e:
            self.logger.error(f"Failed to register with manager: {e}")
            self.logger.info("Will retry registration on heartbeat...")
        
        # Start heartbeat thread
        self.running = True
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()
        
        # Main job processing loop
        self._job_loop()
    
    def stop(self):
        """Stop the agent"""
        self.logger.info("Stopping agent...")
        self.running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
    
    def _heartbeat_loop(self):
        """Background heartbeat loop"""
        while self.running:
            try:
                status = "scanning" if self.current_job else "idle"
                self.client.heartbeat(status, self.current_job)
                # Check for pending commands from server
                self._check_pending_commands()
                # Flush buffered logs to server
                self.client.flush_logs()
            except Exception as e:
                self.logger.warning(f"Heartbeat error: {e}")
            
            time.sleep(self.config.heartbeat_interval)
    
    def _check_pending_commands(self):
        """Check for and execute pending commands from the server"""
        try:
            commands = self.client.get_pending_commands()
            for cmd in commands:
                self._execute_command(cmd)
        except Exception as e:
            self.logger.debug(f"Command check failed: {e}")
    
    def _execute_command(self, cmd: Dict):
        """Execute a command from the server"""
        command = cmd.get("command")
        command_id = str(cmd.get("id"))
        params = cmd.get("parameters", {})
        
        self.logger.info(f"🎯 Executing command: {command}")
        result_data = {}
        
        try:
            if command == "list_paths":
                result_data = self._list_available_paths()
            elif command == "restart":
                self.logger.info("Restart command received - will restart after this heartbeat cycle")
                result_data = {"status": "restart_scheduled"}
                # Schedule restart after command completion
                threading.Timer(5.0, self._restart_agent).start()
            elif command == "update":
                self.logger.info("Update command received")
                result_data = {"status": "update_not_implemented"}
            elif command == "clear_cache":
                result_data = {"status": "cache_cleared"}
            else:
                self.logger.warning(f"Unknown command: {command}")
                result_data = {"error": f"Unknown command: {command}"}
            
            # Report completion
            self.client.complete_command(command_id, result_data)
            self.logger.info(f"✅ Command {command} completed")
            
        except Exception as e:
            self.logger.error(f"Command {command} failed: {e}")
            self.client.complete_command(command_id, {"error": str(e)})
    
    def _list_available_paths(self) -> Dict:
        """List available scan paths on this machine"""
        paths = []
        
        if platform.system() == "Windows":
            # Check common Windows paths
            for drive in ['C', 'D', 'E', 'F']:
                drive_path = f"{drive}:\\"
                if os.path.exists(drive_path):
                    paths.append(drive_path)
                    # Add common directories
                    for subdir in ['Users', 'Projects', 'repos', 'code', 'workspace']:
                        check_path = os.path.join(drive_path, subdir)
                        if os.path.exists(check_path):
                            paths.append(check_path)
        else:
            # Linux/Mac paths
            paths = ['/home', '/opt', '/var', '/etc']
            paths = [p for p in paths if os.path.exists(p)]
        
        self.logger.info(f"📁 Discovered {len(paths)} paths: {paths}")
        return {"paths": paths, "count": len(paths)}
    
    def _restart_agent(self):
        """Restart this agent process"""
        self.logger.info("🔄 Restarting agent...")
        self.running = False
        # Re-execute the current script
        os.execv(sys.executable, [sys.executable] + sys.argv)
    
    def _job_loop(self):
        """Main job processing loop"""
        while self.running:
            try:
                # Check resource usage
                if not self._check_resources():
                    self.logger.debug("Resource limits exceeded, waiting...")
                    time.sleep(self.config.job_poll_interval)
                    continue
                
                # Get pending jobs
                jobs = self.client.get_pending_jobs()
                
                for job in jobs:
                    if not self.running:
                        break
                    
                    job_id = job.get("id")
                    if not job_id:
                        continue
                    
                    # Try to claim the job
                    if self.client.claim_job(job_id):
                        self.logger.info(f"Claimed job {job_id}")
                        self._process_job(job)
            
            except Exception as e:
                self.logger.error(f"Job loop error: {e}")
            
            time.sleep(self.config.job_poll_interval)
    
    def _check_resources(self) -> bool:
        """Check if resource usage is within limits"""
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory().percent
        
        if cpu > self.config.max_cpu_percent:
            return False
        if memory > (self.config.max_memory_mb / psutil.virtual_memory().total * 100 * 1024 * 1024):
            return False
        
        return True
    
    def _process_job(self, job: Dict):
        """Process a scan job"""
        job_id = job.get("id")
        self.current_job = job_id
        
        try:
            target_path = job.get("target_path")
            scan_type = job.get("scan_type", "full")
            options = job.get("options", {})
            
            self.logger.info(f"Processing job {job_id}: {target_path}")
            
            # Validate target path exists and is accessible
            if not os.path.exists(target_path):
                raise ValueError(f"Target path does not exist: {target_path}")
            
            # Run scans
            all_findings = []
            
            # Determine which scanners to use
            scanners_to_use = options.get("scanners", list(self.scanners.keys()))
            
            for scanner_name in scanners_to_use:
                if scanner_name in self.scanners:
                    scanner = self.scanners[scanner_name]
                    self.logger.info(f"Running {scanner_name} scanner...")
                    
                    try:
                        findings = scanner.scan(target_path, options)
                        self.logger.info(f"{scanner_name} found {len(findings)} issues")
                        all_findings.extend(findings)
                    except Exception as e:
                        self.logger.error(f"{scanner_name} scanner error: {e}")
            
            # Deduplicate findings
            all_findings = self._deduplicate_findings(all_findings)
            
            # Submit results
            self.logger.info(f"Job {job_id} complete. Found {len(all_findings)} total findings")
            self.client.submit_results(job_id, all_findings)
        
        except Exception as e:
            self.logger.error(f"Job {job_id} failed: {e}")
            self.client.report_error(job_id, str(e))
        
        finally:
            self.current_job = None
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings"""
        seen = set()
        unique = []
        
        for finding in findings:
            key = (finding.get("file"), finding.get("line"), finding.get("rule"))
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique


# ============================================================================
# WINDOWS SERVICE SUPPORT
# ============================================================================

def run_as_service():
    """Run agent as a Windows service"""
    # Create early startup log for debugging
    startup_log = None
    try:
        if platform.system() == "Windows":
            log_dir = r"C:\Program Files\SecretSnipe\logs"
        else:
            log_dir = "/var/log/secretsnipe"
        os.makedirs(log_dir, exist_ok=True)
        startup_log = os.path.join(log_dir, "startup_debug.log")
        
        with open(startup_log, 'a') as f:
            f.write(f"\n{'='*50}\n")
            f.write(f"Service startup at {datetime.now().isoformat()}\n")
            f.write(f"Python version: {sys.version}\n")
            f.write(f"Working directory: {os.getcwd()}\n")
            f.write(f"Platform: {platform.system()} {platform.version()}\n")
    except Exception as e:
        pass  # Can't even log the error
    
    def log_startup(msg):
        if startup_log:
            try:
                with open(startup_log, 'a') as f:
                    f.write(f"{datetime.now().isoformat()} - {msg}\n")
            except:
                pass
    
    if platform.system() != "Windows":
        print("Service mode is only supported on Windows")
        sys.exit(1)
    
    # Load configuration
    config_path = r"C:\Program Files\SecretSnipe\config\agent_config.json"
    log_startup(f"Looking for config at: {config_path}")
    
    if not os.path.exists(config_path):
        log_startup(f"ERROR: Configuration not found: {config_path}")
        print(f"Configuration not found: {config_path}")
        sys.exit(1)
    
    try:
        # Use utf-8-sig to handle possible BOM from PowerShell
        with open(config_path, 'r', encoding='utf-8-sig') as f:
            config_data = json.load(f)
        log_startup(f"Config loaded successfully, manager URL: {config_data.get('manager', {}).get('url', 'NOT SET')}")
    except Exception as e:
        log_startup(f"ERROR loading config: {e}")
        print(f"Error loading config: {e}")
        sys.exit(1)
    
    # Create config object
    try:
        config = AgentConfig(
            manager_url=config_data.get("manager", {}).get("url", ""),
            api_key=config_data.get("manager", {}).get("api_key", ""),
            log_level=config_data.get("agent", {}).get("log_level", "INFO"),
            heartbeat_interval=config_data.get("agent", {}).get("heartbeat_interval", 30),
            job_poll_interval=config_data.get("agent", {}).get("job_poll_interval", 10),
            enable_custom=config_data.get("scanners", {}).get("custom", {}).get("enabled", True),
            enable_gitleaks=config_data.get("scanners", {}).get("gitleaks", {}).get("enabled", False),
            enable_trufflehog=config_data.get("scanners", {}).get("trufflehog", {}).get("enabled", False),
            gitleaks_path=config_data.get("scanners", {}).get("gitleaks", {}).get("path", ""),
            max_cpu_percent=config_data.get("resource_limits", {}).get("max_cpu_percent", 50),
            max_memory_mb=config_data.get("resource_limits", {}).get("max_memory_mb", 512),
            verify_ssl=config_data.get("manager", {}).get("verify_ssl", True),
            machine_fingerprint=config_data.get("agent", {}).get("machine_fingerprint", "")
        )
        log_startup(f"AgentConfig created successfully")
    except Exception as e:
        log_startup(f"ERROR creating AgentConfig: {e}")
        print(f"Error creating AgentConfig: {e}")
        sys.exit(1)
    
    # Run agent
    try:
        log_startup("Creating SecretSnipeEnterpriseAgent...")
        agent = SecretSnipeEnterpriseAgent(config)
        log_startup("Starting agent...")
        agent.start()
    except KeyboardInterrupt:
        log_startup("Received KeyboardInterrupt, stopping...")
        agent.stop()
    except Exception as e:
        log_startup(f"ERROR running agent: {e}")
        import traceback
        log_startup(f"Traceback: {traceback.format_exc()}")
        raise


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="SecretSnipe Enterprise Agent")
    parser.add_argument("--service", action="store_true", help="Run as Windows service")
    parser.add_argument("--config", type=str, help="Path to config file")
    parser.add_argument("--manager-url", type=str, help="Manager URL")
    parser.add_argument("--api-key", type=str, help="API key")
    parser.add_argument("--log-level", type=str, default="INFO", help="Log level")
    parser.add_argument("--scan", type=str, help="Run a one-time scan on specified path")
    
    args = parser.parse_args()
    
    if args.service:
        run_as_service()
        return
    
    # Load config from file or command line
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config_data = json.load(f)
        config = AgentConfig(
            manager_url=config_data.get("manager", {}).get("url", args.manager_url or ""),
            api_key=config_data.get("manager", {}).get("api_key", args.api_key or ""),
            log_level=args.log_level
        )
    elif args.manager_url and args.api_key:
        config = AgentConfig(
            manager_url=args.manager_url,
            api_key=args.api_key,
            log_level=args.log_level
        )
    else:
        parser.print_help()
        print("\nError: Either --config or both --manager-url and --api-key are required")
        sys.exit(1)
    
    # One-time scan mode
    if args.scan:
        logger = setup_logging(config, os.getcwd())
        scanner = CustomRegexScanner(logger)
        findings = scanner.scan(args.scan)
        
        print(f"\nFound {len(findings)} potential secrets:\n")
        for finding in findings:
            print(f"  [{finding['severity']}] {finding['rule']}")
            print(f"    File: {finding['file']}:{finding['line']}")
            print(f"    Match: {finding['match']}")
            print()
        
        sys.exit(0 if not findings else 1)
    
    # Run as daemon
    agent = SecretSnipeEnterpriseAgent(config)
    
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
