#!/usr/bin/env python3
"""
SecretSnipe Agent - Standalone Windows Version
Copy this file to your Windows server and run it.

Requirements: pip install requests psutil

Usage:
  python secretsnipe_agent.py

Configure via environment variables or edit the CONFIG section below.
"""

import os
import sys
import json
import time
import socket
import logging
import platform
import threading
import re
from pathlib import Path
from datetime import datetime

# ==================== CONFIGURATION ====================
# Edit these or set environment variables

CONFIG = {
    "MANAGER_URL": os.getenv("SECRETSNIPE_MANAGER_URL", "http://10.150.110.24:8443"),
    "API_KEY": os.getenv("SECRETSNIPE_API_KEY", "G7HEyqLjUfpB-nes--YzsbYMYXuQNiQfeYDjxuxUSC5-nDZBylR8CsMr_PtsWQSdR-Sz7jsUwdMDCMpefPSX2w"),
    "HEARTBEAT_INTERVAL": 30,
    "POLL_INTERVAL": 10,
    "MAX_FILE_SIZE": 10 * 1024 * 1024,  # 10MB
}

# ==================== DEPENDENCIES ====================
try:
    import requests
    import psutil
except ImportError:
    print("ERROR: Missing dependencies. Run: pip install requests psutil")
    sys.exit(1)

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("secretsnipe-agent")

# Remote log buffer for sending logs to manager API
_remote_log_buffer = []
_remote_log_buffer_max = 50  # Flush every 50 logs


class RemoteLogHandler(logging.Handler):
    """Custom logging handler that buffers logs for remote submission"""
    
    def emit(self, record):
        global _remote_log_buffer
        try:
            log_entry = {
                "timestamp": self.format(record).split(' - ')[0] if ' - ' in self.format(record) else record.created,
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


# Add remote handler to logger
_remote_handler = RemoteLogHandler()
_remote_handler.setLevel(logging.INFO)
logger.addHandler(_remote_handler)

# ==================== SIGNATURES ====================
# Full signature set matching main SecretSnipe scanner
SIGNATURES = [
    # Critical - Cloud Provider Keys
    {"name": "AWS Access Key ID", "pattern": r"(?:^|[^A-Z0-9])AKIA[0-9A-Z]{16}(?:[^A-Z0-9]|$)", "severity": "critical"},
    {"name": "AWS Secret Access Key", "pattern": r"(?i)(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "severity": "critical"},
    {"name": "Azure Storage Key", "pattern": r"(?i)(?:account[_-]?key|storage[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{86}==)['\"]?", "severity": "critical"},
    {"name": "Azure Connection String", "pattern": r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==", "severity": "critical"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z_-]{35}", "severity": "high"},
    {"name": "Google OAuth Token", "pattern": r"ya29\.[0-9A-Za-z_-]{50,}", "severity": "high"},
    
    # Critical - API Provider Keys
    {"name": "GitHub Token", "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}", "severity": "critical"},
    {"name": "GitLab Token", "pattern": r"glpat-[0-9A-Za-z_-]{20}", "severity": "critical"},
    {"name": "Slack Token", "pattern": r"xox[baprs]-[0-9A-Za-z-]{10,}", "severity": "high"},
    {"name": "Slack Webhook", "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{20,}", "severity": "high"},
    {"name": "Discord Webhook", "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "severity": "high"},
    {"name": "Discord Bot Token", "pattern": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "severity": "critical"},
    
    # Critical - Payment & AI
    {"name": "Stripe Live Key", "pattern": r"(?:sk|rk)_live_[0-9A-Za-z]{24,}", "severity": "critical"},
    {"name": "Stripe Test Key", "pattern": r"(?:sk|pk)_test_[0-9A-Za-z]{24,}", "severity": "medium"},
    {"name": "OpenAI API Key", "pattern": r"sk-[A-Za-z0-9]{48}", "severity": "critical"},
    {"name": "Anthropic API Key", "pattern": r"sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{93}", "severity": "critical"},
    
    # Critical - Communication Services
    {"name": "SendGrid API Key", "pattern": r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}", "severity": "high"},
    {"name": "Twilio API Key", "pattern": r"SK[0-9a-fA-F]{32}", "severity": "high"},
    {"name": "Twilio Auth Token", "pattern": r"(?i)twilio[_-]?(?:auth[_-]?)?token\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?", "severity": "critical"},
    {"name": "Mailchimp API Key", "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}", "severity": "high"},
    
    # Critical - Database & Infrastructure  
    {"name": "Database Connection String", "pattern": r"(?i)(?:jdbc|mysql|postgresql|mongodb(?:\+srv)?|redis|mssql|oracle)://(?:[\w.-]+:[^@\s]+@)[\w.:/-]+", "severity": "critical"},
    {"name": "Private Key", "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA |ENCRYPTED )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "DigitalOcean Token", "pattern": r"dop_v1_[a-f0-9]{64}", "severity": "critical"},
    {"name": "Heroku API Key", "pattern": r"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?", "severity": "high"},
    {"name": "Shopify Access Token", "pattern": r"shpat_[a-fA-F0-9]{32}", "severity": "critical"},
    
    # High - Package Registry Tokens
    {"name": "NPM Token", "pattern": r"npm_[A-Za-z0-9]{36}", "severity": "high"},
    {"name": "PyPI API Token", "pattern": r"pypi-[A-Za-z0-9_]{50,}", "severity": "high"},
    
    # High - Auth Tokens
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9-_]{20,}\.eyJ[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_.+/]{20,}", "severity": "high"},
    {"name": "Bearer Token", "pattern": r"(?i)bearer\s+[a-zA-Z0-9-._~+/]{20,}=*", "severity": "high"},
    {"name": "Basic Auth Header", "pattern": r"(?i)authorization\s*[:=]\s*['\"]?basic\s+[A-Za-z0-9+/]{20,}={0,2}['\"]?", "severity": "high"},
    
    # High - PII
    {"name": "Credit Card Number", "pattern": r"(?i)(?:card|credit|payment|visa|mastercard|amex|discover|pan|ccn|cardnum)[^\n]{0,40}\b(?:4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}|6(?:011|5[0-9]{2})[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})\b", "severity": "critical"},
    {"name": "Social Security Number", "pattern": r"(?i)(?:ssn|social[\s_-]*security|soc[\s_-]*sec)\s*(?:number|num|no|#)?\s*[:=]?\s*['\"]?(\d{3}-\d{2}-\d{4})['\"]?", "severity": "high"},
    {"name": "Email with Password", "pattern": r"(?i)email\s*[:=]\s*['\"][\w.-]+@[\w.-]+['\"]\s*[,;\n]?\s*password\s*[:=]\s*['\"][^'\"]{6,}['\"]", "severity": "critical"},
    
    # Medium - Generic Secrets (more permissive patterns)
    {"name": "Hardcoded Password", "pattern": r"(?i)(?:password|passwd|pwd|secret|token)\s*[:=]\s*(?!true|false|null|none|undefined|empty|changeme|placeholder|example|\${|\[|\{\{|\b\w+\b\.|\s*['\"]{{0,2}}$)['\"]?([^'\"\s,;$%<>\n\r]{8,64})['\"]?", "severity": "high"},
    {"name": "API Key", "pattern": r"(?i)api[_-]?key\s*[:=]\s*['\"]?(?!your|example|placeholder|changeme|xxx)([a-zA-Z0-9-_.]{20,64})['\"]?", "severity": "high"},
    {"name": "Datadog API Key", "pattern": r"(?i)datadog[_-]?api[_-]?key\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?", "severity": "high"},
]

SKIP_EXTENSIONS = {'.exe', '.dll', '.so', '.bin', '.pyc', '.class', '.jar', '.zip', '.tar', '.gz',
                   '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.mp3', '.mp4', '.pdf', '.msi'}
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', 'vendor', 'dist', 'build', 
             'Windows', 'Program Files', 'ProgramData', '$Recycle.Bin'}

# ==================== AGENT CLASS ====================
class SecretSnipeAgent:
    def __init__(self):
        self.manager_url = CONFIG["MANAGER_URL"].rstrip('/')
        self.api_key = CONFIG["API_KEY"]
        self.agent_id = None
        self.hostname = socket.gethostname()
        self.running = False
        
        # Compile patterns
        self.compiled_patterns = []
        for sig in SIGNATURES:
            try:
                self.compiled_patterns.append({
                    "name": sig["name"],
                    "pattern": re.compile(sig["pattern"]),
                    "severity": sig["severity"]
                })
                logger.debug(f"Loaded pattern: {sig['name']}")
            except re.error as e:
                logger.warning(f"Invalid pattern for {sig['name']}: {e}")
        logger.info(f"Loaded {len(self.compiled_patterns)} secret patterns")
    
    def _get_headers(self):
        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        if self.agent_id:
            headers["X-Agent-ID"] = self.agent_id
        return headers
    
    def _api_request(self, method, endpoint, data=None):
        url = f"{self.manager_url}/api/v1{endpoint}"
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
    
    def _flush_logs(self):
        """Send buffered logs to the manager API"""
        global _remote_log_buffer
        if not self.agent_id or not _remote_log_buffer:
            return
        
        # Grab buffer and reset
        logs_to_send = _remote_log_buffer[:50]  # Send max 50 at a time
        _remote_log_buffer = _remote_log_buffer[50:]
        
        try:
            result = self._api_request("POST", f"/agents/{self.agent_id}/logs", {"logs": logs_to_send})
            if result and result.get("success"):
                logger.debug(f"📤 Flushed {len(logs_to_send)} logs to server")
        except Exception as e:
            # Put logs back if send failed
            _remote_log_buffer = logs_to_send + _remote_log_buffer
            logger.debug(f"Log flush failed: {e}")
    
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
        logger.info(f"Registering agent {self.hostname} with {self.manager_url}...")
        
        data = {
            "hostname": self.hostname,
            "ip_address": self._get_ip(),
            "os_type": platform.system(),
            "os_version": platform.release(),
            "agent_version": "1.0.0",
            "capabilities": ["custom"]
        }
        
        result = self._api_request("POST", "/agents/register", data)
        if result and result.get("success"):
            self.agent_id = result.get("data", {}).get("agent_id")
            logger.info(f"✅ Registered with agent_id: {self.agent_id}")
            return True
        logger.error("❌ Failed to register")
        return False
    
    def send_heartbeat(self):
        while self.running:
            try:
                data = {
                    "agent_id": self.agent_id,
                    "status": "online",
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('C:\\').percent if platform.system() == 'Windows' else psutil.disk_usage('/').percent,
                    "uptime_seconds": int(time.time() - psutil.boot_time())
                }
                result = self._api_request("POST", "/agents/heartbeat", data)
                if result:
                    logger.debug("💓 Heartbeat sent")
                    # Check for pending commands
                    self._check_pending_commands()
                    # Flush buffered logs to server
                    self._flush_logs()
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
            
            time.sleep(CONFIG["HEARTBEAT_INTERVAL"])
    
    def _check_pending_commands(self):
        """Check for and execute pending commands from the server"""
        try:
            result = self._api_request("GET", f"/agents/{self.agent_id}/commands")
            if result and result.get("success") and result.get("data"):
                for cmd in result["data"]:
                    self._execute_command(cmd)
        except Exception as e:
            logger.debug(f"Command check failed: {e}")
    
    def _execute_command(self, cmd):
        """Execute a command from the server"""
        command = cmd.get("command")
        command_id = str(cmd.get("id"))
        params = cmd.get("parameters", {})
        
        logger.info(f"🎯 Executing command: {command}")
        result_data = {}
        
        try:
            if command == "list_paths":
                result_data = self._list_available_paths()
            elif command == "restart":
                # Complete command before restart
                self._complete_command(command_id, {"status": "restarting"})
                self._restart_agent()
                return
            elif command == "update":
                result_data = self._update_agent(params.get("version", "latest"))
            elif command == "clear_cache":
                result_data = {"cleared": True}
            elif command == "uninstall":
                # Complete command before uninstall
                self._complete_command(command_id, {"status": "uninstalling"})
                self._uninstall_agent(wipe_config=params.get("wipe_config", True))
                return
            else:
                result_data = {"error": f"Unknown command: {command}"}
            
            # Report completion
            self._complete_command(command_id, result_data)
            
        except Exception as e:
            logger.error(f"Command {command} failed: {e}")
            self._complete_command(command_id, {"error": str(e)})
    
    def _complete_command(self, command_id: str, result: dict):
        """Report command completion to server"""
        try:
            self._api_request("POST", f"/agents/{self.agent_id}/commands/{command_id}/complete", result)
        except Exception as e:
            logger.error(f"Failed to report command completion: {e}")
    
    def _list_available_paths(self) -> dict:
        """List available drives/paths on this machine"""
        paths = []
        
        if platform.system() == "Windows":
            import string
            import ctypes
            
            # Use Windows API to get all logical drives (more reliable)
            try:
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drive = f"{letter}:\\"
                        try:
                            usage = psutil.disk_usage(drive)
                            # Determine drive type
                            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                            type_names = {0: "unknown", 1: "no_root", 2: "removable", 
                                         3: "fixed", 4: "network", 5: "cdrom", 6: "ramdisk"}
                            paths.append({
                                "path": drive,
                                "type": type_names.get(drive_type, "drive"),
                                "total_gb": round(usage.total / (1024**3), 2),
                                "free_gb": round(usage.free / (1024**3), 2)
                            })
                        except PermissionError:
                            paths.append({"path": drive, "type": "inaccessible"})
                        except Exception:
                            paths.append({"path": drive, "type": "drive"})
                    bitmask >>= 1
            except Exception as e:
                logger.warning(f"Could not enumerate drives via API: {e}")
                # Fallback to simple check
                for letter in string.ascii_uppercase:
                    drive = f"{letter}:\\"
                    if Path(drive).exists():
                        try:
                            usage = psutil.disk_usage(drive)
                            paths.append({
                                "path": drive,
                                "type": "drive",
                                "total_gb": round(usage.total / (1024**3), 2),
                                "free_gb": round(usage.free / (1024**3), 2)
                            })
                        except:
                            paths.append({"path": drive, "type": "drive"})
            
            # Enumerate network shares using net use command
            try:
                import subprocess
                result = subprocess.run(['net', 'use'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '\\\\' in line:
                            parts = line.split()
                            for part in parts:
                                if part.startswith('\\\\'):
                                    unc_path = part.strip()
                                    if Path(unc_path).exists():
                                        paths.append({"path": unc_path, "type": "network_share"})
                                        logger.info(f"📁 Found network share: {unc_path}")
            except Exception as e:
                logger.debug(f"Could not enumerate network shares: {e}")
        else:
            # Linux - list mount points
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    paths.append({
                        "path": part.mountpoint,
                        "type": part.fstype,
                        "total_gb": round(usage.total / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2)
                    })
                except:
                    paths.append({"path": part.mountpoint, "type": part.fstype})
        
        logger.info(f"📁 Discovered {len(paths)} paths")
        return {"paths": [p["path"] for p in paths], "details": paths}
    
    def _restart_agent(self):
        """Restart the agent (platform-specific)"""
        logger.info("🔄 Restarting agent...")
        if platform.system() == "Windows":
            # For Windows service, request restart through service manager
            import subprocess
            try:
                subprocess.run(["sc", "stop", "SecretSnipeAgent"], capture_output=True)
                time.sleep(2)
                subprocess.run(["sc", "start", "SecretSnipeAgent"], capture_output=True)
            except Exception as e:
                logger.error(f"Restart failed: {e}")
                # Fallback - exit and let service manager restart
                sys.exit(0)
        else:
            # Linux - exit and let systemd/supervisor restart
            sys.exit(0)
    
    def _update_agent(self, version: str) -> dict:
        """Update the agent to a new version"""
        logger.info(f"⬆️ Updating agent to version: {version}")
        try:
            # Download new version from manager
            update_url = f"{self.manager_url}/api/v1/agent/download"
            response = requests.get(update_url, headers=self._get_headers(), timeout=60)
            
            if response.status_code == 200:
                # Save update script
                update_path = Path("secretsnipe_agent_new.py")
                update_path.write_bytes(response.content)
                
                logger.info(f"Update downloaded to {update_path}")
                return {"status": "downloaded", "version": version, "path": str(update_path)}
            else:
                return {"error": f"Download failed: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def _uninstall_agent(self, wipe_config: bool = True):
        """Uninstall the agent - stop service and optionally wipe config"""
        logger.info(f"🗑️ Uninstalling agent (wipe_config={wipe_config})...")
        
        if platform.system() == "Windows":
            import subprocess
            import shutil
            
            install_path = Path(os.getenv("SECRETSNIPE_INSTALL_PATH", r"C:\Program Files\SecretSnipe"))
            
            try:
                # Stop the service first
                logger.info("Stopping service...")
                subprocess.run(["sc", "stop", "SecretSnipeAgent"], capture_output=True)
                time.sleep(2)
                
                if wipe_config:
                    # Wipe configuration files
                    config_path = install_path / "config"
                    if config_path.exists():
                        logger.info(f"Wiping config at {config_path}")
                        shutil.rmtree(config_path, ignore_errors=True)
                    
                    # Wipe fingerprint/registration data
                    for f in ["agent_config.json", "machine_fingerprint.txt", ".registered"]:
                        fp = install_path / f
                        if fp.exists():
                            fp.unlink()
                            logger.info(f"Removed {f}")
                
                # Remove the service registration
                logger.info("Removing service registration...")
                nssm_path = install_path / "nssm.exe"
                if nssm_path.exists():
                    subprocess.run([str(nssm_path), "remove", "SecretSnipeAgent", "confirm"], capture_output=True)
                else:
                    subprocess.run(["sc", "delete", "SecretSnipeAgent"], capture_output=True)
                
                logger.info("Agent uninstalled successfully")
                
            except Exception as e:
                logger.error(f"Uninstall error: {e}")
            
            # Exit the process
            sys.exit(0)
        else:
            # Linux - stop systemd service and exit
            import subprocess
            try:
                subprocess.run(["systemctl", "stop", "secretsnipe-agent"], capture_output=True)
                subprocess.run(["systemctl", "disable", "secretsnipe-agent"], capture_output=True)
                
                if wipe_config:
                    config_paths = [
                        Path("/etc/secretsnipe/config.json"),
                        Path("/var/lib/secretsnipe/"),
                        Path.home() / ".secretsnipe/"
                    ]
                    for p in config_paths:
                        if p.exists():
                            if p.is_dir():
                                import shutil
                                shutil.rmtree(p, ignore_errors=True)
                            else:
                                p.unlink()
                            logger.info(f"Removed {p}")
            except Exception as e:
                logger.error(f"Uninstall error: {e}")
            
            sys.exit(0)
    
    def _mount_network_share(self, unc_path: str, username: str = None, password: str = None, drive_letter: str = None) -> str:
        """
        Mount a network share (CIFS/SMB) on Windows.
        
        Args:
            unc_path: UNC path like \\\\server\\share
            username: Domain\\username or just username
            password: Password for the share
            drive_letter: Optional drive letter to map (e.g., 'Z:')
            
        Returns:
            The path to use for scanning (drive letter if mapped, else UNC)
        """
        if platform.system() != "Windows":
            logger.warning("Network share mounting only supported on Windows")
            return unc_path
        
        import subprocess
        
        # Normalize the path
        unc_path = unc_path.replace('/', '\\')
        if not unc_path.startswith('\\\\'):
            unc_path = '\\\\' + unc_path.lstrip('\\')
        
        try:
            # Check if share is already accessible
            if Path(unc_path).exists():
                logger.info(f"Network share already accessible: {unc_path}")
                return unc_path
            
            # Try to mount with credentials
            if drive_letter:
                # Map to a drive letter
                cmd = ['net', 'use', drive_letter, unc_path]
                if username and password:
                    cmd.extend([f'/user:{username}', password])
                cmd.append('/persistent:no')
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info(f"Mapped {unc_path} to {drive_letter}")
                    return drive_letter
                else:
                    logger.error(f"Failed to map drive: {result.stderr}")
            else:
                # Just establish the connection without mapping
                cmd = ['net', 'use', unc_path]
                if username and password:
                    cmd.extend([f'/user:{username}', password])
                cmd.append('/persistent:no')
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info(f"Connected to network share: {unc_path}")
                    return unc_path
                else:
                    logger.error(f"Failed to connect to share: {result.stderr}")
                    
        except Exception as e:
            logger.error(f"Error mounting network share {unc_path}: {e}")
        
        return unc_path
    
    def _unmount_network_share(self, path: str):
        """Unmount a previously mounted network share"""
        if platform.system() != "Windows":
            return
        
        import subprocess
        
        try:
            # Only unmount if it's a drive letter we mapped
            if len(path) == 2 and path[1] == ':':
                subprocess.run(['net', 'use', path, '/delete', '/y'], capture_output=True)
                logger.info(f"Unmounted {path}")
        except Exception as e:
            logger.warning(f"Error unmounting {path}: {e}")
    
    def poll_for_jobs(self):
        while self.running:
            try:
                result = self._api_request("GET", f"/jobs/poll?agent_id={self.agent_id}")
                if result and result.get("success") and result.get("data"):
                    job = result["data"]
                    logger.info(f"📋 Received job: {job.get('job_id')}")
                    self._execute_job(job)
            except Exception as e:
                logger.error(f"Job poll failed: {e}")
            
            time.sleep(CONFIG["POLL_INTERVAL"])
    
    def _execute_job(self, job):
        job_id = job.get("job_id")
        scan_paths = job.get("scan_paths", [])
        share_credentials = job.get("share_credentials", {})  # Optional credentials for network shares
        
        logger.info(f"🔍 Starting job {job_id} on {len(scan_paths)} paths")
        
        # Update status to running
        self._api_request("POST", "/jobs/status", {"job_id": job_id, "status": "running"})
        
        all_findings = []
        files_scanned = 0
        mounted_shares = []  # Track what we mounted so we can clean up
        
        try:
            for scan_path in scan_paths:
                actual_path = scan_path
                
                # Check if this is a network share (UNC path)
                if scan_path.startswith('\\\\') or scan_path.startswith('//'):
                    # Try to mount the share
                    share_creds = share_credentials.get(scan_path, {})
                    actual_path = self._mount_network_share(
                        scan_path,
                        username=share_creds.get('username'),
                        password=share_creds.get('password'),
                        drive_letter=share_creds.get('drive_letter')
                    )
                    if actual_path != scan_path:
                        mounted_shares.append(actual_path)
                
                path = Path(actual_path)
                if not path.exists():
                    logger.warning(f"Path not found: {scan_path}")
                    continue
                
                findings, count = self._scan_path(path)
                all_findings.extend(findings)
                files_scanned += count
            
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
            
            logger.info(f"✅ Job {job_id} completed: {files_scanned} files, {len(all_findings)} findings")
            
        except Exception as e:
            logger.error(f"❌ Job {job_id} failed: {e}")
            self._api_request("POST", "/jobs/status", {
                "job_id": job_id,
                "status": "failed",
                "error_message": str(e)
            })
        finally:
            # Clean up any mounted shares
            for share in mounted_shares:
                self._unmount_network_share(share)
    
    def _scan_path(self, path):
        findings = []
        files_scanned = 0
        
        if path.is_file():
            files = [path]
        else:
            files = self._get_files(path)
        
        logger.info(f"   Found {len(files)} file(s) to scan in {path}")
        
        for file_path in files:
            try:
                file_size = file_path.stat().st_size
                if file_size > CONFIG["MAX_FILE_SIZE"]:
                    logger.debug(f"   Skipping {file_path} (too large: {file_size} bytes)")
                    continue
                
                files_scanned += 1
                logger.info(f"   Scanning: {file_path} ({file_size} bytes)")
                
                # Try multiple encodings (handles UTF-16 LE BOM, UTF-8 BOM, etc.)
                content = None
                for encoding in ['utf-8-sig', 'utf-16', 'utf-16-le', 'utf-8', 'latin-1']:
                    try:
                        content = file_path.read_text(encoding=encoding)
                        logger.debug(f"   Read with encoding: {encoding}")
                        break
                    except (UnicodeDecodeError, UnicodeError):
                        continue
                
                if content is None:
                    content = file_path.read_text(errors='ignore')
                    logger.warning(f"   Fallback to ignore errors for {file_path}")
                
                lines = content.split('\n')
                
                file_findings = 0
                for pattern_info in self.compiled_patterns:
                    for line_num, line in enumerate(lines, 1):
                        for match in pattern_info["pattern"].finditer(line):
                            file_findings += 1
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
                
                if file_findings > 0:
                    logger.info(f"   ⚠️  Found {file_findings} secret(s) in {file_path.name}")
                else:
                    logger.debug(f"   No secrets found in {file_path.name}")
                            
            except Exception as e:
                logger.warning(f"   Error scanning {file_path}: {e}")
        
        return findings, files_scanned
    
    def _get_files(self, directory):
        files = []
        try:
            for item in directory.rglob('*'):
                if item.is_file():
                    if item.suffix.lower() in SKIP_EXTENSIONS:
                        continue
                    if any(skip.lower() in str(item).lower() for skip in SKIP_DIRS):
                        continue
                    files.append(item)
        except Exception as e:
            logger.error(f"Error walking {directory}: {e}")
        return files
    
    def _submit_findings(self, job_id, findings):
        logger.info(f"📤 Submitting {len(findings)} findings for job {job_id}")
        
        batch_size = 100
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            self._api_request("POST", "/findings/submit", {
                "job_id": job_id,
                "agent_id": self.agent_id,
                "findings": batch
            })
    
    def start(self):
        logger.info("🚀 Starting SecretSnipe Agent...")
        logger.info(f"   Manager: {self.manager_url}")
        logger.info(f"   Hostname: {self.hostname}")
        
        if not self.manager_url or not self.api_key:
            logger.error("Manager URL and API key are required")
            return False
        
        if not self.register():
            return False
        
        self.running = True
        
        # Start heartbeat thread
        threading.Thread(target=self.send_heartbeat, daemon=True).start()
        logger.info("💓 Heartbeat thread started")
        
        # Start job polling thread
        threading.Thread(target=self.poll_for_jobs, daemon=True).start()
        logger.info("📋 Job polling thread started")
        
        return True
    
    def stop(self):
        logger.info("🛑 Stopping agent...")
        self.running = False
    
    def run_forever(self):
        if not self.start():
            return
        
        logger.info("=" * 50)
        logger.info("Agent running. Press Ctrl+C to stop.")
        logger.info("=" * 50)
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║        SecretSnipe Agent - Windows Version            ║
    ║                                                       ║
    ║  Configure via environment variables or edit CONFIG   ║
    ║  at the top of this script.                           ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    agent = SecretSnipeAgent()
    agent.run_forever()
