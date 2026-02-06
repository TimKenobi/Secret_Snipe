#!/usr/bin/env python3
"""
SecretSnipe Agent - Core Agent Service
Lightweight agent that runs on remote hosts to scan for secrets.

Features:
- Registers with management server
- Sends heartbeats
- Polls for scan jobs
- Executes scans locally
- Reports findings back to manager
"""

import os
import sys
import time
import json
import signal
import logging
import platform
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
import uuid
import hashlib
import re

import requests
import psutil

# Add parent directory for shared imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import (
    AgentStatus, JobStatus, AgentInfo, ScanJob, Finding, Heartbeat, APIResponse
)
from shared.config import AgentConfig, API_VERSION, HEARTBEAT_INTERVAL_SECONDS


class SecretSnipeAgent:
    """
    SecretSnipe Agent - runs on remote hosts to perform local secret scanning.
    
    The agent:
    1. Registers with the management server
    2. Sends periodic heartbeats
    3. Polls for available scan jobs
    4. Executes scans locally using configured scanners
    5. Reports findings back to the manager
    """
    
    VERSION = "1.0.0"
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.agent_id = config.agent_id or self._generate_agent_id()
        self.running = False
        self.current_job: Optional[ScanJob] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.job_poll_thread: Optional[threading.Thread] = None
        
        # Setup logging
        self.logger = logging.getLogger("secretsnipe-agent")
        self._setup_logging()
        
        # Load signature patterns
        self.signatures = self._load_signatures()
        
        # Session for API calls
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": self.config.api_key,
            "X-Agent-ID": self.agent_id,
            "Content-Type": "application/json",
            "User-Agent": f"SecretSnipe-Agent/{self.VERSION}"
        })
        self.session.verify = self.config.verify_ssl
        
        self.logger.info(f"Agent initialized with ID: {self.agent_id}")
    
    def _setup_logging(self):
        """Configure logging"""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(f'/tmp/secretsnipe-agent-{self.agent_id[:8]}.log')
            ]
        )
    
    def _generate_agent_id(self) -> str:
        """Generate a unique agent ID based on hardware"""
        hostname = platform.node()
        mac = uuid.getnode()
        unique_str = f"{hostname}-{mac}-{platform.system()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]
    
    def _load_signatures(self) -> List[Dict[str, Any]]:
        """Load secret detection signatures"""
        # Default patterns - can be extended from manager
        return [
            {
                "name": "AWS Access Key",
                "pattern": r"AKIA[0-9A-Z]{16}",
                "severity": "Critical",
                "confidence": 0.95
            },
            {
                "name": "AWS Secret Key",
                "pattern": r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
                "severity": "Critical",
                "confidence": 0.9
            },
            {
                "name": "Generic API Key",
                "pattern": r"(?i)(?:api[_\-\.]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})",
                "severity": "High",
                "confidence": 0.7
            },
            {
                "name": "Generic Secret",
                "pattern": r"(?i)(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\",]{8,})",
                "severity": "High",
                "confidence": 0.6
            },
            {
                "name": "Private Key",
                "pattern": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                "severity": "Critical",
                "confidence": 0.99
            },
            {
                "name": "GitHub Token",
                "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
                "severity": "Critical",
                "confidence": 0.95
            },
            {
                "name": "Slack Token",
                "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
                "severity": "High",
                "confidence": 0.95
            },
            {
                "name": "Database Connection String",
                "pattern": r"(?i)(?:mysql|postgresql|postgres|mongodb|redis):\/\/[^\s]+",
                "severity": "Critical",
                "confidence": 0.9
            },
            {
                "name": "JWT Token",
                "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                "severity": "High",
                "confidence": 0.85
            },
            {
                "name": "Azure Storage Key",
                "pattern": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
                "severity": "Critical",
                "confidence": 0.95
            }
        ]
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for registration"""
        return {
            "hostname": platform.node(),
            "os_type": platform.system().lower(),
            "os_version": platform.version(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_total_gb": round(psutil.disk_usage('/').total / (1024**3), 2)
        }
    
    def _get_capabilities(self) -> List[str]:
        """Detect available scanning capabilities"""
        capabilities = ["custom"]  # Always have custom scanner
        
        # Check for trufflehog
        try:
            result = subprocess.run(["trufflehog", "--version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                capabilities.append("trufflehog")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Check for gitleaks
        try:
            result = subprocess.run(["gitleaks", "version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                capabilities.append("gitleaks")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        return capabilities
    
    def _api_call(self, method: str, endpoint: str, data: dict = None) -> Optional[dict]:
        """Make an API call to the manager"""
        url = f"{self.config.manager_url}/api/{API_VERSION}{endpoint}"
        
        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=30)
            elif method.upper() == "POST":
                response = self.session.post(url, json=data, timeout=30)
            elif method.upper() == "PUT":
                response = self.session.put(url, json=data, timeout=30)
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return None
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                self.logger.error("Authentication failed - check API key")
                return None
            elif response.status_code == 404:
                self.logger.warning(f"Endpoint not found: {endpoint}")
                return None
            else:
                self.logger.error(f"API error {response.status_code}: {response.text}")
                return None
                
        except requests.exceptions.ConnectionError:
            self.logger.error(f"Cannot connect to manager at {self.config.manager_url}")
            return None
        except requests.exceptions.Timeout:
            self.logger.error("API request timed out")
            return None
        except Exception as e:
            self.logger.error(f"API call failed: {e}")
            return None
    
    def register(self) -> bool:
        """Register agent with the management server"""
        self.logger.info("Registering with management server...")
        
        system_info = self._get_system_info()
        capabilities = self._get_capabilities()
        
        agent_info = AgentInfo(
            agent_id=self.agent_id,
            hostname=system_info["hostname"],
            ip_address=self._get_ip_address(),
            os_type=system_info["os_type"],
            os_version=system_info["os_version"],
            agent_version=self.VERSION,
            scan_paths=self.config.scan_paths,
            capabilities=capabilities,
            status=AgentStatus.ONLINE,
            registered_at=datetime.now(),
            metadata=system_info
        )
        
        response = self._api_call("POST", "/agents/register", agent_info.to_dict())
        
        if response and response.get("success"):
            self.logger.info(f"Successfully registered agent: {self.agent_id}")
            # Update agent_id if server assigned a different one
            if response.get("data", {}).get("agent_id"):
                self.agent_id = response["data"]["agent_id"]
                self.session.headers["X-Agent-ID"] = self.agent_id
            return True
        else:
            self.logger.error("Failed to register with management server")
            return False
    
    def _get_ip_address(self) -> str:
        """Get the primary IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "unknown"
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to manager"""
        try:
            heartbeat = Heartbeat(
                agent_id=self.agent_id,
                timestamp=datetime.now(),
                status=AgentStatus.SCANNING if self.current_job else AgentStatus.ONLINE,
                current_job_id=self.current_job.job_id if self.current_job else None,
                cpu_percent=psutil.cpu_percent(),
                memory_percent=psutil.virtual_memory().percent,
                disk_percent=psutil.disk_usage('/').percent
            )
            
            response = self._api_call("POST", "/agents/heartbeat", heartbeat.to_dict())
            return response and response.get("success", False)
            
        except Exception as e:
            self.logger.error(f"Failed to send heartbeat: {e}")
            return False
    
    def _heartbeat_loop(self):
        """Background thread for sending heartbeats"""
        while self.running:
            self.send_heartbeat()
            time.sleep(self.config.heartbeat_interval)
    
    def poll_for_jobs(self) -> Optional[ScanJob]:
        """Check for available scan jobs"""
        response = self._api_call("GET", f"/agents/{self.agent_id}/jobs")
        
        if response and response.get("success") and response.get("data"):
            job_data = response["data"]
            if job_data:
                return ScanJob.from_dict(job_data)
        
        return None
    
    def _job_poll_loop(self):
        """Background thread for polling jobs"""
        while self.running:
            if not self.current_job:
                job = self.poll_for_jobs()
                if job:
                    self.logger.info(f"Received job: {job.job_id}")
                    self._execute_job(job)
            time.sleep(5)  # Poll every 5 seconds
    
    def _execute_job(self, job: ScanJob):
        """Execute a scan job"""
        self.current_job = job
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now()
        
        # Notify manager job started
        self._api_call("POST", f"/jobs/{job.job_id}/status", {
            "status": "running",
            "started_at": job.started_at.isoformat()
        })
        
        self.logger.info(f"Starting job {job.job_id} - scanning {len(job.scan_paths)} paths")
        
        all_findings = []
        files_scanned = 0
        
        try:
            for scan_path in job.scan_paths:
                if not os.path.exists(scan_path):
                    self.logger.warning(f"Path does not exist: {scan_path}")
                    continue
                
                # Run custom scanner
                if "custom" in job.scanners:
                    findings, count = self._scan_path_custom(scan_path, job)
                    all_findings.extend(findings)
                    files_scanned += count
                
                # Run trufflehog if available
                if "trufflehog" in job.scanners and "trufflehog" in self._get_capabilities():
                    findings = self._scan_path_trufflehog(scan_path, job)
                    all_findings.extend(findings)
                
                # Run gitleaks if available
                if "gitleaks" in job.scanners and "gitleaks" in self._get_capabilities():
                    findings = self._scan_path_gitleaks(scan_path, job)
                    all_findings.extend(findings)
                
                # Send findings in batches
                if len(all_findings) >= 100:
                    self._submit_findings(job.job_id, all_findings)
                    all_findings = []
            
            # Submit remaining findings
            if all_findings:
                self._submit_findings(job.job_id, all_findings)
            
            # Job completed
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now()
            job.files_scanned = files_scanned
            
            self._api_call("POST", f"/jobs/{job.job_id}/status", {
                "status": "completed",
                "completed_at": job.completed_at.isoformat(),
                "files_scanned": files_scanned,
                "findings_count": job.findings_count
            })
            
            self.logger.info(f"Job {job.job_id} completed - {job.findings_count} findings in {files_scanned} files")
            
        except Exception as e:
            self.logger.error(f"Job {job.job_id} failed: {e}")
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            
            self._api_call("POST", f"/jobs/{job.job_id}/status", {
                "status": "failed",
                "error_message": str(e)
            })
        
        finally:
            self.current_job = None
    
    def _scan_path_custom(self, path: str, job: ScanJob) -> tuple:
        """Scan a path using custom regex patterns"""
        findings = []
        files_scanned = 0
        
        try:
            if os.path.isfile(path):
                file_findings = self._scan_file(path, job)
                findings.extend(file_findings)
                files_scanned = 1
            else:
                for root, dirs, files in os.walk(path):
                    # Skip excluded directories
                    dirs[:] = [d for d in dirs if not self._should_exclude(d, job.exclude_patterns)]
                    
                    for filename in files:
                        if self._should_exclude(filename, job.exclude_patterns):
                            continue
                        
                        file_path = os.path.join(root, filename)
                        
                        # Skip large files
                        try:
                            if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB
                                continue
                        except OSError:
                            continue
                        
                        file_findings = self._scan_file(file_path, job)
                        findings.extend(file_findings)
                        files_scanned += 1
        
        except Exception as e:
            self.logger.error(f"Error scanning {path}: {e}")
        
        return findings, files_scanned
    
    def _scan_file(self, file_path: str, job: ScanJob) -> List[Finding]:
        """Scan a single file for secrets"""
        findings = []
        
        try:
            # Try to read file
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except (IOError, PermissionError):
                return findings
            
            lines = content.split('\n')
            
            for sig in self.signatures:
                pattern = re.compile(sig["pattern"], re.IGNORECASE | re.MULTILINE)
                
                for match in pattern.finditer(content):
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Get context (line before, match line, line after)
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 2)
                    context = '\n'.join(lines[start_line:end_line])
                    
                    # Mask the secret value
                    secret_value = match.group(0)
                    masked_value = self._mask_secret(secret_value)
                    
                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        job_id=job.job_id,
                        agent_id=self.agent_id,
                        file_path=file_path,
                        line_number=line_num,
                        secret_type=sig["name"],
                        secret_value=masked_value,
                        context=context[:500],  # Limit context size
                        severity=sig["severity"],
                        confidence_score=sig["confidence"],
                        tool_source="custom"
                    )
                    
                    findings.append(finding)
                    job.findings_count += 1
        
        except Exception as e:
            self.logger.debug(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    def _mask_secret(self, secret: str) -> str:
        """Mask a secret value for safe storage"""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
    
    def _should_exclude(self, name: str, patterns: List[str]) -> bool:
        """Check if a file/dir should be excluded"""
        import fnmatch
        for pattern in patterns:
            if fnmatch.fnmatch(name, pattern):
                return True
        return False
    
    def _scan_path_trufflehog(self, path: str, job: ScanJob) -> List[Finding]:
        """Scan using trufflehog"""
        findings = []
        
        try:
            cmd = ["trufflehog", "filesystem", path, "--json", "--no-update"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        job_id=job.job_id,
                        agent_id=self.agent_id,
                        file_path=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                        line_number=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line"),
                        secret_type=data.get("DetectorName", "Unknown"),
                        secret_value=self._mask_secret(data.get("Raw", "")),
                        context=data.get("Raw", "")[:200],
                        severity="High",
                        confidence_score=0.9,
                        tool_source="trufflehog",
                        metadata={"verified": data.get("Verified", False)}
                    )
                    findings.append(finding)
                    job.findings_count += 1
                except json.JSONDecodeError:
                    continue
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Trufflehog scan timed out for {path}")
        except Exception as e:
            self.logger.error(f"Trufflehog error: {e}")
        
        return findings
    
    def _scan_path_gitleaks(self, path: str, job: ScanJob) -> List[Finding]:
        """Scan using gitleaks"""
        findings = []
        
        try:
            output_file = f"/tmp/gitleaks-{job.job_id}.json"
            cmd = ["gitleaks", "detect", "--source", path, "--report-format", "json", 
                   "--report-path", output_file, "--no-git"]
            
            subprocess.run(cmd, capture_output=True, timeout=1800)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    results = json.load(f)
                
                for item in results:
                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        job_id=job.job_id,
                        agent_id=self.agent_id,
                        file_path=item.get("File", ""),
                        line_number=item.get("StartLine"),
                        secret_type=item.get("RuleID", "Unknown"),
                        secret_value=self._mask_secret(item.get("Secret", "")),
                        context=item.get("Match", "")[:200],
                        severity="High",
                        confidence_score=0.85,
                        tool_source="gitleaks"
                    )
                    findings.append(finding)
                    job.findings_count += 1
                
                os.remove(output_file)
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Gitleaks scan timed out for {path}")
        except Exception as e:
            self.logger.error(f"Gitleaks error: {e}")
        
        return findings
    
    def _submit_findings(self, job_id: str, findings: List[Finding]):
        """Submit findings to the manager"""
        findings_data = [f.to_dict() for f in findings]
        
        response = self._api_call("POST", f"/jobs/{job_id}/findings", {
            "findings": findings_data
        })
        
        if response and response.get("success"):
            self.logger.debug(f"Submitted {len(findings)} findings for job {job_id}")
        else:
            self.logger.error(f"Failed to submit findings for job {job_id}")
    
    def start(self):
        """Start the agent"""
        self.logger.info("Starting SecretSnipe Agent...")
        
        # Register with manager
        if not self.register():
            self.logger.error("Failed to register - exiting")
            return False
        
        self.running = True
        
        # Start heartbeat thread
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        
        # Start job polling thread
        self.job_poll_thread = threading.Thread(target=self._job_poll_loop, daemon=True)
        self.job_poll_thread.start()
        
        self.logger.info("Agent started successfully")
        return True
    
    def stop(self):
        """Stop the agent"""
        self.logger.info("Stopping SecretSnipe Agent...")
        self.running = False
        
        # Send offline status
        try:
            self._api_call("POST", "/agents/heartbeat", {
                "agent_id": self.agent_id,
                "timestamp": datetime.now().isoformat(),
                "status": "offline"
            })
        except Exception:
            pass
        
        self.logger.info("Agent stopped")
    
    def run_forever(self):
        """Run the agent until interrupted"""
        if not self.start():
            sys.exit(1)
        
        # Setup signal handlers
        def signal_handler(signum, frame):
            self.logger.info("Received shutdown signal")
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Keep main thread alive
        while self.running:
            time.sleep(1)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="SecretSnipe Agent")
    parser.add_argument("--manager-url", help="Manager API URL", 
                        default=os.getenv("SECRETSNIPE_MANAGER_URL", "https://localhost:8443"))
    parser.add_argument("--api-key", help="API Key for authentication",
                        default=os.getenv("SECRETSNIPE_API_KEY"))
    parser.add_argument("--scan-paths", help="Comma-separated list of paths to scan",
                        default=os.getenv("SECRETSNIPE_SCAN_PATHS", ""))
    parser.add_argument("--log-level", help="Log level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--no-verify-ssl", action="store_true", 
                        help="Disable SSL verification (not recommended)")
    
    args = parser.parse_args()
    
    if not args.api_key:
        print("ERROR: API key is required. Set SECRETSNIPE_API_KEY or use --api-key")
        sys.exit(1)
    
    config = AgentConfig(
        manager_url=args.manager_url,
        api_key=args.api_key,
        scan_paths=args.scan_paths.split(",") if args.scan_paths else [],
        log_level=args.log_level,
        verify_ssl=not args.no_verify_ssl
    )
    
    agent = SecretSnipeAgent(config)
    agent.run_forever()


if __name__ == "__main__":
    main()
