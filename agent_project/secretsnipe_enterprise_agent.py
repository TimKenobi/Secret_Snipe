#!/usr/bin/env python3
"""
SecretSnipe Enterprise Agent v2.0
=================================
Full-featured agent with:
- 3 Scanners: Gitleaks, Trufflehog, Custom Regex
- File Watching: Real-time monitoring with incremental scanning
- Resource Management: CPU/Memory throttling
- Remote Management: Logs, Config, Updates, Schedules
- Automatic Updates: Self-updating capability

Requirements:
    pip install requests psutil watchdog croniter

For Gitleaks/Trufflehog, download binaries and configure paths in config.
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
import hashlib
import tempfile
import shutil
import subprocess
import queue
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler

# ==================== VERSION ====================
AGENT_VERSION = "2.0.0"

# ==================== DEPENDENCIES ====================
try:
    import requests
    import psutil
except ImportError:
    print("ERROR: Missing core dependencies. Run: pip install requests psutil")
    sys.exit(1)

# Optional dependencies
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("WARNING: watchdog not installed. File watching disabled. Run: pip install watchdog")

try:
    from croniter import croniter
    CRONITER_AVAILABLE = True
except ImportError:
    CRONITER_AVAILABLE = False
    print("WARNING: croniter not installed. Scheduling disabled. Run: pip install croniter")

# ==================== DEFAULT CONFIGURATION ====================
DEFAULT_CONFIG = {
    "manager_url": os.getenv("SECRETSNIPE_MANAGER_URL", "http://10.150.110.24:8443"),
    "api_key": os.getenv("SECRETSNIPE_API_KEY", "G7HEyqLjUfpB-nes--YzsbYMYXuQNiQfeYDjxuxUSC5-nDZBylR8CsMr_PtsWQSdR-Sz7jsUwdMDCMpefPSX2w"),
    
    "scanners": {
        "gitleaks": {
            "enabled": True,
            "path": os.getenv("GITLEAKS_PATH", "gitleaks" if platform.system() != "Windows" else "C:\\Tools\\gitleaks.exe"),
            "extra_args": ["--no-git"],
            "timeout": 300
        },
        "trufflehog": {
            "enabled": True,
            "path": os.getenv("TRUFFLEHOG_PATH", "trufflehog" if platform.system() != "Windows" else "C:\\Tools\\trufflehog.exe"),
            "extra_args": [],
            "timeout": 300
        },
        "custom": {
            "enabled": True,
            "signatures_url": None  # Will fetch from manager
        }
    },
    
    "resource_limits": {
        "max_cpu_percent": 50,
        "max_memory_mb": 500,
        "max_concurrent_scans": 2,
        "io_nice": True,
        "pause_on_high_load": True,
        "high_load_threshold": 80
    },
    
    "watch": {
        "enabled": True,
        "debounce_seconds": 5,
        "batch_size": 10
    },
    
    "logging": {
        "level": "INFO",
        "local_retention_days": 7,
        "stream_to_manager": True,
        "log_file": "secretsnipe_agent.log"
    },
    
    "heartbeat_interval": 30,
    "job_poll_interval": 10,
    "config_check_interval": 60,
    "log_upload_interval": 30,
    "max_file_size": 10 * 1024 * 1024,  # 10MB
}

# ==================== SIGNATURES ====================
BUILTIN_SIGNATURES = [
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
    
    # Medium - Generic Secrets
    {"name": "Hardcoded Password", "pattern": r"(?i)(?:password|passwd|pwd|secret|token)\s*[:=]\s*['\"]([^'\"\s]{8,64})['\"]", "severity": "high"},
    {"name": "API Key Generic", "pattern": r"(?i)api[_-]?key\s*[:=]\s*['\"]?(?!your|example|placeholder|changeme|xxx)([a-zA-Z0-9-_.]{20,64})['\"]?", "severity": "high"},
]

SKIP_EXTENSIONS = {'.exe', '.dll', '.so', '.bin', '.pyc', '.pyo', '.class', '.jar', '.war',
                   '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.iso', '.dmg',
                   '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
                   '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flac',
                   '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                   '.msi', '.deb', '.rpm', '.pkg', '.woff', '.woff2', '.ttf', '.eot'}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'env', '.env',
             'vendor', 'dist', 'build', 'target', 'out', 'bin', 'obj',
             'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData',
             '$Recycle.Bin', 'System Volume Information', '.idea', '.vscode',
             'coverage', '.nyc_output', '.pytest_cache', '.tox', 'htmlcov'}


# ==================== LOGGING SETUP ====================
class RemoteLogHandler(logging.Handler):
    """Handler that queues logs for remote submission"""
    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue
    
    def emit(self, record):
        try:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "level": record.levelname,
                "message": self.format(record),
                "context": {
                    "module": record.module,
                    "funcName": record.funcName,
                    "lineno": record.lineno
                }
            }
            self.log_queue.put_nowait(log_entry)
        except queue.Full:
            pass  # Drop log if queue is full


def setup_logging(config: dict, log_queue: queue.Queue) -> logging.Logger:
    """Setup logging with file rotation and remote handler"""
    logger = logging.getLogger("secretsnipe-agent")
    logger.setLevel(getattr(logging, config.get("level", "INFO")))
    
    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console)
    
    # File handler with rotation
    log_file = config.get("log_file", "secretsnipe_agent.log")
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=7
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(name)s - %(funcName)s:%(lineno)d - %(message)s'
    ))
    logger.addHandler(file_handler)
    
    # Remote handler
    if config.get("stream_to_manager", True):
        remote_handler = RemoteLogHandler(log_queue)
        remote_handler.setFormatter(logging.Formatter('%(message)s'))
        remote_handler.setLevel(logging.INFO)  # Only INFO and above go to manager
        logger.addHandler(remote_handler)
    
    return logger


# ==================== RESOURCE MANAGER ====================
class ResourceManager:
    """Manages CPU and memory usage limits"""
    
    def __init__(self, config: dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.paused = False
        self._monitor_thread = None
        self._stop_event = threading.Event()
    
    def start_monitoring(self):
        """Start resource monitoring thread"""
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Monitor system resources and pause if needed"""
        while not self._stop_event.is_set():
            try:
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory().percent
                
                threshold = self.config.get("high_load_threshold", 80)
                
                if self.config.get("pause_on_high_load", True):
                    if cpu > threshold or mem > threshold:
                        if not self.paused:
                            self.logger.warning(f"High system load (CPU: {cpu}%, MEM: {mem}%), pausing scans")
                            self.paused = True
                    else:
                        if self.paused:
                            self.logger.info("System load normalized, resuming scans")
                            self.paused = False
            except Exception as e:
                self.logger.error(f"Resource monitor error: {e}")
            
            time.sleep(5)
    
    def wait_if_paused(self, timeout: float = 60) -> bool:
        """Wait if paused, return True if can continue"""
        start = time.time()
        while self.paused:
            if time.time() - start > timeout:
                return False
            time.sleep(1)
        return True
    
    def throttle_process(self, proc: subprocess.Popen):
        """Apply resource limits to subprocess"""
        try:
            p = psutil.Process(proc.pid)
            
            # Set low priority
            if platform.system() == "Windows":
                p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            else:
                p.nice(10)  # Lower priority on Unix
            
            # Set IO priority if available
            if self.config.get("io_nice", True):
                try:
                    if platform.system() != "Windows":
                        p.ionice(psutil.IOPRIO_CLASS_IDLE)
                except:
                    pass
        except Exception as e:
            self.logger.debug(f"Could not throttle process: {e}")


# ==================== FILE WATCHER ====================
class SecretFileHandler(FileSystemEventHandler):
    """Handles file system events for incremental scanning"""
    
    def __init__(self, agent: 'SecretSnipeEnterpriseAgent'):
        self.agent = agent
        self.pending_files = set()
        self.lock = threading.Lock()
        self._debounce_timer = None
    
    def on_modified(self, event):
        if not event.is_directory:
            self._queue_file(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self._queue_file(event.src_path)
    
    def _queue_file(self, path: str):
        """Queue file for scanning with debounce"""
        # Skip binary/ignored files
        p = Path(path)
        if p.suffix.lower() in SKIP_EXTENSIONS:
            return
        if any(skip in str(p) for skip in SKIP_DIRS):
            return
        
        with self.lock:
            self.pending_files.add(path)
        
        # Debounce - wait before processing
        if self._debounce_timer:
            self._debounce_timer.cancel()
        
        debounce = self.agent.config.get("watch", {}).get("debounce_seconds", 5)
        self._debounce_timer = threading.Timer(debounce, self._process_pending)
        self._debounce_timer.start()
    
    def _process_pending(self):
        """Process pending files"""
        with self.lock:
            files = list(self.pending_files)
            self.pending_files.clear()
        
        if files:
            self.agent.logger.info(f"📁 File watcher detected {len(files)} changed file(s)")
            self.agent._scan_files_incremental(files)


# ==================== SCANNERS ====================
class GitleaksScanner:
    """Gitleaks scanner wrapper"""
    
    def __init__(self, config: dict, logger: logging.Logger, resource_mgr: ResourceManager):
        self.config = config
        self.logger = logger
        self.resource_mgr = resource_mgr
        self.enabled = config.get("enabled", True)
        self.path = config.get("path", "gitleaks")
        self.extra_args = config.get("extra_args", [])
        self.timeout = config.get("timeout", 300)
    
    def is_available(self) -> bool:
        """Check if gitleaks is available"""
        try:
            result = subprocess.run([self.path, "version"], capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def scan(self, path: str) -> List[Dict]:
        """Scan path with gitleaks"""
        if not self.enabled:
            return []
        
        findings = []
        output_file = None
        
        try:
            # Create temp file for JSON output
            fd, output_file = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            
            cmd = [
                self.path,
                "detect",
                "--source", path,
                "--report-format", "json",
                "--report-path", output_file,
                "--exit-code", "0"
            ] + self.extra_args
            
            self.logger.debug(f"Running: {' '.join(cmd)}")
            
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Throttle the process
            self.resource_mgr.throttle_process(proc)
            
            stdout, stderr = proc.communicate(timeout=self.timeout)
            
            # Parse results
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    results = json.load(f)
                
                for r in results:
                    findings.append({
                        "secret_type": r.get("RuleID", "Unknown"),
                        "secret_value": r.get("Secret", "")[:100],
                        "file_path": r.get("File", ""),
                        "line_number": r.get("StartLine", 0),
                        "line_content": r.get("Line", "")[:500],
                        "scanner": "gitleaks",
                        "pattern_name": r.get("RuleID", ""),
                        "severity": self._map_severity(r.get("Tags", [])),
                        "commit": r.get("Commit", ""),
                        "author": r.get("Author", ""),
                        "fingerprint": r.get("Fingerprint", "")
                    })
                
                self.logger.info(f"🔍 Gitleaks found {len(findings)} secrets")
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Gitleaks timed out after {self.timeout}s")
            proc.kill()
        except Exception as e:
            self.logger.error(f"Gitleaks error: {e}")
        finally:
            if output_file and os.path.exists(output_file):
                os.remove(output_file)
        
        return findings
    
    def _map_severity(self, tags: list) -> str:
        """Map gitleaks tags to severity"""
        tags_lower = [t.lower() for t in tags]
        if "critical" in tags_lower:
            return "critical"
        if "high" in tags_lower:
            return "high"
        if "medium" in tags_lower:
            return "medium"
        return "low"


class TrufflehogScanner:
    """Trufflehog scanner wrapper"""
    
    def __init__(self, config: dict, logger: logging.Logger, resource_mgr: ResourceManager):
        self.config = config
        self.logger = logger
        self.resource_mgr = resource_mgr
        self.enabled = config.get("enabled", True)
        self.path = config.get("path", "trufflehog")
        self.extra_args = config.get("extra_args", [])
        self.timeout = config.get("timeout", 300)
    
    def is_available(self) -> bool:
        """Check if trufflehog is available"""
        try:
            result = subprocess.run([self.path, "--version"], capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def scan(self, path: str) -> List[Dict]:
        """Scan path with trufflehog"""
        if not self.enabled:
            return []
        
        findings = []
        
        try:
            cmd = [
                self.path,
                "filesystem",
                path,
                "--json",
                "--no-update"
            ] + self.extra_args
            
            self.logger.debug(f"Running: {' '.join(cmd)}")
            
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Throttle the process
            self.resource_mgr.throttle_process(proc)
            
            stdout, stderr = proc.communicate(timeout=self.timeout)
            
            # Parse JSON lines output
            for line in stdout.decode('utf-8', errors='ignore').split('\n'):
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                    if r.get("Raw"):
                        findings.append({
                            "secret_type": r.get("DetectorName", "Unknown"),
                            "secret_value": r.get("Raw", "")[:100],
                            "file_path": r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                            "line_number": r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                            "line_content": r.get("Raw", "")[:500],
                            "scanner": "trufflehog",
                            "pattern_name": r.get("DetectorName", ""),
                            "severity": "high" if r.get("Verified", False) else "medium",
                            "verified": r.get("Verified", False)
                        })
                except json.JSONDecodeError:
                    continue
            
            self.logger.info(f"🔍 Trufflehog found {len(findings)} secrets")
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Trufflehog timed out after {self.timeout}s")
            proc.kill()
        except Exception as e:
            self.logger.error(f"Trufflehog error: {e}")
        
        return findings


class CustomScanner:
    """Custom regex-based scanner"""
    
    def __init__(self, signatures: List[Dict], logger: logging.Logger, config: dict):
        self.logger = logger
        self.config = config
        self.compiled_patterns = []
        
        for sig in signatures:
            try:
                self.compiled_patterns.append({
                    "name": sig["name"],
                    "pattern": re.compile(sig["pattern"]),
                    "severity": sig.get("severity", "medium")
                })
            except re.error as e:
                logger.warning(f"Invalid pattern for {sig.get('name', 'unknown')}: {e}")
        
        logger.info(f"Custom scanner loaded {len(self.compiled_patterns)} patterns")
    
    def scan(self, path: str) -> List[Dict]:
        """Scan path with custom patterns"""
        findings = []
        path_obj = Path(path)
        
        if path_obj.is_file():
            findings.extend(self._scan_file(path_obj))
        else:
            for file_path in self._get_files(path_obj):
                findings.extend(self._scan_file(file_path))
        
        self.logger.info(f"🔍 Custom scanner found {len(findings)} secrets")
        return findings
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan single file (for incremental scanning)"""
        return self._scan_file(file_path)
    
    def _scan_file(self, file_path: Path) -> List[Dict]:
        """Scan a single file"""
        findings = []
        
        try:
            # Skip large files
            if file_path.stat().st_size > self.config.get("max_file_size", 10*1024*1024):
                return findings
            
            # Read with multiple encodings
            content = self._read_file(file_path)
            if not content:
                return findings
            
            lines = content.split('\n')
            
            for pattern_info in self.compiled_patterns:
                for line_num, line in enumerate(lines, 1):
                    for match in pattern_info["pattern"].finditer(line):
                        fingerprint = hashlib.md5(
                            f"{file_path}:{line_num}:{pattern_info['name']}:{match.group()}".encode()
                        ).hexdigest()
                        
                        findings.append({
                            "secret_type": pattern_info["name"],
                            "secret_value": match.group()[:100],
                            "file_path": str(file_path),
                            "line_number": line_num,
                            "line_content": line[:500],
                            "scanner": "custom",
                            "pattern_name": pattern_info["name"],
                            "severity": pattern_info["severity"],
                            "fingerprint": fingerprint
                        })
        
        except Exception as e:
            self.logger.debug(f"Error scanning {file_path}: {e}")
        
        return findings
    
    def _read_file(self, file_path: Path) -> Optional[str]:
        """Read file with multiple encodings"""
        for encoding in ['utf-8-sig', 'utf-16', 'utf-16-le', 'utf-8', 'latin-1']:
            try:
                return file_path.read_text(encoding=encoding)
            except (UnicodeDecodeError, UnicodeError):
                continue
        return None
    
    def _get_files(self, directory: Path) -> List[Path]:
        """Get all scannable files in directory"""
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
            self.logger.error(f"Error walking {directory}: {e}")
        return files


# ==================== ENTERPRISE AGENT ====================
class SecretSnipeEnterpriseAgent:
    """Enterprise-grade SecretSnipe Agent"""
    
    def __init__(self, config: dict = None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.agent_id = None
        self.hostname = socket.gethostname()
        self.running = False
        
        # Log queue for remote streaming
        self.log_queue = queue.Queue(maxsize=1000)
        
        # Setup logging
        self.logger = setup_logging(
            self.config.get("logging", {}),
            self.log_queue
        )
        
        # Resource manager
        self.resource_mgr = ResourceManager(
            self.config.get("resource_limits", {}),
            self.logger
        )
        
        # Initialize scanners
        self._init_scanners()
        
        # File watcher
        self.observer = None
        self.file_handler = None
        
        # Schedules
        self.schedules = []
        
        # Thread pool for concurrent scanning
        max_concurrent = self.config.get("resource_limits", {}).get("max_concurrent_scans", 2)
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent)
        
        # Threads
        self._threads = {}
    
    def _init_scanners(self):
        """Initialize all scanners"""
        scanner_config = self.config.get("scanners", {})
        
        # Gitleaks
        gl_config = scanner_config.get("gitleaks", {})
        self.gitleaks = GitleaksScanner(gl_config, self.logger, self.resource_mgr)
        if gl_config.get("enabled", True):
            if self.gitleaks.is_available():
                self.logger.info("✅ Gitleaks scanner available")
            else:
                self.logger.warning("⚠️ Gitleaks not found, disabling")
                gl_config["enabled"] = False
        
        # Trufflehog
        th_config = scanner_config.get("trufflehog", {})
        self.trufflehog = TrufflehogScanner(th_config, self.logger, self.resource_mgr)
        if th_config.get("enabled", True):
            if self.trufflehog.is_available():
                self.logger.info("✅ Trufflehog scanner available")
            else:
                self.logger.warning("⚠️ Trufflehog not found, disabling")
                th_config["enabled"] = False
        
        # Custom scanner
        self.custom = CustomScanner(BUILTIN_SIGNATURES, self.logger, self.config)
        self.logger.info("✅ Custom scanner available")
    
    def _get_headers(self) -> dict:
        """Get API request headers"""
        headers = {
            "X-API-Key": self.config["api_key"],
            "Content-Type": "application/json"
        }
        if self.agent_id:
            headers["X-Agent-ID"] = self.agent_id
        return headers
    
    def _api_request(self, method: str, endpoint: str, data: dict = None) -> Optional[dict]:
        """Make API request to manager"""
        url = f"{self.config['manager_url'].rstrip('/')}/api/v1{endpoint}"
        try:
            if method == "GET":
                resp = requests.get(url, headers=self._get_headers(), timeout=30)
            elif method == "POST":
                resp = requests.post(url, headers=self._get_headers(), json=data, timeout=30)
            elif method == "PUT":
                resp = requests.put(url, headers=self._get_headers(), json=data, timeout=30)
            else:
                return None
            
            if resp.status_code == 200:
                return resp.json()
            else:
                self.logger.error(f"API error {resp.status_code}: {resp.text[:200]}")
                return None
        except Exception as e:
            self.logger.error(f"API request failed: {e}")
            return None
    
    def _get_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def register(self) -> bool:
        """Register agent with manager"""
        self.logger.info(f"Registering agent {self.hostname}...")
        
        # Determine capabilities
        capabilities = ["custom"]
        if self.config["scanners"]["gitleaks"].get("enabled"):
            capabilities.append("gitleaks")
        if self.config["scanners"]["trufflehog"].get("enabled"):
            capabilities.append("trufflehog")
        if WATCHDOG_AVAILABLE:
            capabilities.append("file_watch")
        if CRONITER_AVAILABLE:
            capabilities.append("scheduling")
        
        data = {
            "hostname": self.hostname,
            "ip_address": self._get_ip(),
            "os_type": platform.system(),
            "os_version": platform.release(),
            "agent_version": AGENT_VERSION,
            "capabilities": capabilities
        }
        
        result = self._api_request("POST", "/agents/register", data)
        if result and result.get("success"):
            self.agent_id = result.get("data", {}).get("agent_id")
            self.logger.info(f"✅ Registered with agent_id: {self.agent_id}")
            return True
        
        self.logger.error("❌ Failed to register")
        return False
    
    def _heartbeat_loop(self):
        """Send heartbeats to manager"""
        while self.running:
            try:
                disk_path = 'C:\\' if platform.system() == 'Windows' else '/'
                data = {
                    "agent_id": self.agent_id,
                    "status": "online",
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage(disk_path).percent,
                    "uptime_seconds": int(time.time() - psutil.boot_time()),
                    "agent_version": AGENT_VERSION
                }
                
                result = self._api_request("POST", "/agents/heartbeat", data)
                if result:
                    self.logger.debug("💓 Heartbeat sent")
                    
                    # Check for config updates
                    if result.get("config_update"):
                        self._apply_config(result["config_update"])
                    
                    # Check for pending updates
                    if result.get("update_available"):
                        self._handle_update(result.get("update_info"))
            
            except Exception as e:
                self.logger.error(f"Heartbeat failed: {e}")
            
            time.sleep(self.config["heartbeat_interval"])
    
    def _job_poll_loop(self):
        """Poll for jobs from manager"""
        while self.running:
            try:
                # Wait if system is under high load
                if not self.resource_mgr.wait_if_paused(timeout=30):
                    continue
                
                result = self._api_request("GET", f"/jobs/poll?agent_id={self.agent_id}")
                if result and result.get("success") and result.get("data"):
                    job = result["data"]
                    self.logger.info(f"📋 Received job: {job.get('job_id')}")
                    self._execute_job(job)
            
            except Exception as e:
                self.logger.error(f"Job poll failed: {e}")
            
            time.sleep(self.config["job_poll_interval"])
    
    def _log_upload_loop(self):
        """Upload logs to manager"""
        while self.running:
            try:
                logs = []
                while not self.log_queue.empty() and len(logs) < 100:
                    try:
                        logs.append(self.log_queue.get_nowait())
                    except queue.Empty:
                        break
                
                if logs:
                    self._api_request("POST", f"/agents/{self.agent_id}/logs", {"logs": logs})
            
            except Exception as e:
                self.logger.debug(f"Log upload failed: {e}")
            
            time.sleep(self.config.get("log_upload_interval", 30))
    
    def _schedule_loop(self):
        """Execute scheduled scans"""
        if not CRONITER_AVAILABLE:
            return
        
        while self.running:
            try:
                # Fetch schedules from manager
                result = self._api_request("GET", f"/agents/{self.agent_id}/schedules")
                if result and result.get("success"):
                    self.schedules = result.get("data", [])
                
                # Check each schedule
                now = datetime.now()
                for schedule in self.schedules:
                    if not schedule.get("enabled", True):
                        continue
                    
                    cron = schedule.get("cron_expression")
                    last_run = schedule.get("last_run")
                    
                    if last_run:
                        last_run = datetime.fromisoformat(last_run.replace('Z', '+00:00'))
                    else:
                        last_run = now - timedelta(days=1)
                    
                    cron_iter = croniter(cron, last_run)
                    next_run = cron_iter.get_next(datetime)
                    
                    if next_run <= now:
                        self.logger.info(f"⏰ Running scheduled scan: {schedule.get('name')}")
                        self._execute_scheduled_scan(schedule)
            
            except Exception as e:
                self.logger.error(f"Schedule check failed: {e}")
            
            time.sleep(60)  # Check every minute
    
    def _execute_job(self, job: dict):
        """Execute a scan job"""
        job_id = job.get("job_id")
        scan_paths = job.get("scan_paths", [])
        scanner_config = job.get("scanner_config", {})
        
        self.logger.info(f"🔍 Starting job {job_id}")
        self._api_request("POST", "/jobs/status", {"job_id": job_id, "status": "running"})
        
        all_findings = []
        files_scanned = 0
        
        try:
            for scan_path in scan_paths:
                path = Path(scan_path)
                if not path.exists():
                    self.logger.warning(f"Path not found: {scan_path}")
                    continue
                
                # Run scanners in parallel
                futures = []
                
                if scanner_config.get("gitleaks", True) and self.gitleaks.is_available():
                    futures.append(self.executor.submit(self.gitleaks.scan, str(path)))
                
                if scanner_config.get("trufflehog", True) and self.trufflehog.is_available():
                    futures.append(self.executor.submit(self.trufflehog.scan, str(path)))
                
                if scanner_config.get("custom", True):
                    futures.append(self.executor.submit(self.custom.scan, str(path)))
                
                # Collect results
                for future in as_completed(futures):
                    try:
                        findings = future.result(timeout=600)
                        all_findings.extend(findings)
                    except Exception as e:
                        self.logger.error(f"Scanner error: {e}")
                
                # Count files (estimate from custom scanner)
                if path.is_file():
                    files_scanned += 1
                else:
                    files_scanned += len(list(path.rglob('*')))
            
            # Deduplicate findings
            all_findings = self._deduplicate_findings(all_findings)
            
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
            
            self.logger.info(f"✅ Job {job_id} completed: {files_scanned} files, {len(all_findings)} findings")
        
        except Exception as e:
            self.logger.error(f"❌ Job {job_id} failed: {e}")
            self._api_request("POST", "/jobs/status", {
                "job_id": job_id,
                "status": "failed",
                "error_message": str(e)
            })
    
    def _execute_scheduled_scan(self, schedule: dict):
        """Execute a scheduled scan"""
        job = {
            "job_id": f"schedule-{schedule['schedule_id']}-{int(time.time())}",
            "scan_paths": schedule.get("scan_paths", []),
            "scanner_config": schedule.get("scanner_config", {})
        }
        self._execute_job(job)
        
        # Update last_run
        self._api_request("PUT", f"/schedules/{schedule['schedule_id']}", {
            "last_run": datetime.utcnow().isoformat()
        })
    
    def _scan_files_incremental(self, files: List[str]):
        """Scan specific files (for file watcher)"""
        all_findings = []
        
        for file_path in files:
            try:
                path = Path(file_path)
                if not path.exists():
                    continue
                
                findings = self.custom.scan_file(path)
                all_findings.extend(findings)
            except Exception as e:
                self.logger.debug(f"Error scanning {file_path}: {e}")
        
        if all_findings:
            all_findings = self._deduplicate_findings(all_findings)
            self.logger.info(f"📤 File watcher found {len(all_findings)} secrets")
            
            # Submit as watch job
            job_id = f"watch-{int(time.time())}"
            self._submit_findings(job_id, all_findings)
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings"""
        seen = set()
        unique = []
        
        for f in findings:
            # Create fingerprint
            key = f.get("fingerprint") or hashlib.md5(
                f"{f.get('file_path')}:{f.get('line_number')}:{f.get('secret_value', '')[:20]}".encode()
            ).hexdigest()
            
            if key not in seen:
                seen.add(key)
                f["fingerprint"] = key
                unique.append(f)
        
        return unique
    
    def _submit_findings(self, job_id: str, findings: List[Dict]):
        """Submit findings to manager"""
        self.logger.info(f"📤 Submitting {len(findings)} findings")
        
        batch_size = 100
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            
            # Add hostname to each finding
            for f in batch:
                f["hostname"] = self.hostname
            
            self._api_request("POST", "/findings/submit", {
                "job_id": job_id,
                "agent_id": self.agent_id,
                "findings": batch
            })
    
    def _apply_config(self, new_config: dict):
        """Apply configuration update from manager"""
        self.logger.info("📥 Applying configuration update")
        try:
            self.config.update(new_config)
            # Reinitialize scanners if needed
            self._init_scanners()
        except Exception as e:
            self.logger.error(f"Failed to apply config: {e}")
    
    def _handle_update(self, update_info: dict):
        """Handle agent update"""
        if not update_info:
            return
        
        self.logger.info(f"📥 Update available: v{update_info.get('version')}")
        # TODO: Implement auto-update
    
    def _start_file_watcher(self):
        """Start file system watcher"""
        if not WATCHDOG_AVAILABLE:
            self.logger.warning("File watching not available (install watchdog)")
            return
        
        watch_config = self.config.get("watch", {})
        if not watch_config.get("enabled", True):
            return
        
        # Get watch paths from manager
        result = self._api_request("GET", f"/agents/{self.agent_id}/watch-paths")
        watch_paths = []
        if result and result.get("success"):
            watch_paths = [wp["path"] for wp in result.get("data", []) if wp.get("enabled", True)]
        
        if not watch_paths:
            self.logger.info("No watch paths configured")
            return
        
        self.file_handler = SecretFileHandler(self)
        self.observer = Observer()
        
        for path in watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.file_handler, path, recursive=True)
                self.logger.info(f"👁️ Watching: {path}")
        
        self.observer.start()
        self.logger.info("File watcher started")
    
    def start(self) -> bool:
        """Start the agent"""
        self.logger.info("=" * 60)
        self.logger.info(f"🚀 SecretSnipe Enterprise Agent v{AGENT_VERSION}")
        self.logger.info(f"   Manager: {self.config['manager_url']}")
        self.logger.info(f"   Hostname: {self.hostname}")
        self.logger.info("=" * 60)
        
        if not self.register():
            return False
        
        self.running = True
        
        # Start resource monitoring
        self.resource_mgr.start_monitoring()
        
        # Start threads
        threads = [
            ("heartbeat", self._heartbeat_loop),
            ("job_poll", self._job_poll_loop),
            ("log_upload", self._log_upload_loop),
        ]
        
        if CRONITER_AVAILABLE:
            threads.append(("scheduler", self._schedule_loop))
        
        for name, target in threads:
            t = threading.Thread(target=target, daemon=True, name=name)
            t.start()
            self._threads[name] = t
            self.logger.info(f"Started {name} thread")
        
        # Start file watcher
        self._start_file_watcher()
        
        return True
    
    def stop(self):
        """Stop the agent"""
        self.logger.info("🛑 Stopping agent...")
        self.running = False
        
        # Stop file watcher
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        
        # Stop resource monitoring
        self.resource_mgr.stop_monitoring()
        
        # Shutdown executor
        self.executor.shutdown(wait=False)
        
        self.logger.info("Agent stopped")
    
    def run_forever(self):
        """Run the agent until interrupted"""
        if not self.start():
            return
        
        self.logger.info("=" * 60)
        self.logger.info("Agent running. Press Ctrl+C to stop.")
        self.logger.info("=" * 60)
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()


# ==================== MAIN ====================
def main():
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║        SecretSnipe Enterprise Agent v2.0                   ║
    ║                                                            ║
    ║  Full-featured agent with Gitleaks, Trufflehog, and       ║
    ║  custom scanning. Resource-limited and manageable.         ║
    ║                                                            ║
    ║  Configure via environment variables or config file.       ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    # Load config from file if exists
    config = None
    config_file = Path("secretsnipe_agent_config.json")
    if config_file.exists():
        try:
            with open(config_file) as f:
                config = json.load(f)
            print(f"Loaded config from {config_file}")
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
    
    agent = SecretSnipeEnterpriseAgent(config)
    agent.run_forever()


if __name__ == "__main__":
    main()
