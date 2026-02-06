"""
SecretSnipe Agent - Shared Data Models
Common data structures used by both agent and manager.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import json
import hashlib
import uuid


class AgentStatus(str, Enum):
    """Agent connection status"""
    ONLINE = "online"
    OFFLINE = "offline"
    SCANNING = "scanning"
    ERROR = "error"
    PENDING = "pending"  # Registered but never connected


class JobStatus(str, Enum):
    """Scan job status"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobType(str, Enum):
    """Types of scan jobs"""
    FULL_SCAN = "full_scan"
    INCREMENTAL_SCAN = "incremental_scan"
    PATH_SCAN = "path_scan"
    SCHEDULED_SCAN = "scheduled_scan"


@dataclass
class AgentInfo:
    """Information about a registered agent"""
    agent_id: str
    hostname: str
    ip_address: str
    os_type: str  # linux, windows, darwin
    os_version: str
    agent_version: str
    scan_paths: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)  # trufflehog, gitleaks, custom
    status: AgentStatus = AgentStatus.PENDING
    last_heartbeat: Optional[datetime] = None
    registered_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "agent_version": self.agent_version,
            "scan_paths": self.scan_paths,
            "capabilities": self.capabilities,
            "status": self.status.value if isinstance(self.status, AgentStatus) else self.status,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "tags": self.tags,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AgentInfo':
        return cls(
            agent_id=data.get("agent_id", ""),
            hostname=data.get("hostname", ""),
            ip_address=data.get("ip_address", ""),
            os_type=data.get("os_type", ""),
            os_version=data.get("os_version", ""),
            agent_version=data.get("agent_version", ""),
            scan_paths=data.get("scan_paths", []),
            capabilities=data.get("capabilities", []),
            status=AgentStatus(data.get("status", "pending")),
            last_heartbeat=datetime.fromisoformat(data["last_heartbeat"]) if data.get("last_heartbeat") else None,
            registered_at=datetime.fromisoformat(data["registered_at"]) if data.get("registered_at") else None,
            tags=data.get("tags", []),
            metadata=data.get("metadata", {})
        )


@dataclass
class ScanJob:
    """A scan job to be executed by an agent"""
    job_id: str
    agent_id: Optional[str] = None
    job_type: JobType = JobType.FULL_SCAN
    status: JobStatus = JobStatus.PENDING
    scan_paths: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    scanners: List[str] = field(default_factory=lambda: ["custom", "trufflehog", "gitleaks"])
    priority: int = 5  # 1-10, higher = more urgent
    created_at: Optional[datetime] = None
    assigned_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    files_scanned: int = 0
    error_message: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "agent_id": self.agent_id,
            "job_type": self.job_type.value if isinstance(self.job_type, JobType) else self.job_type,
            "status": self.status.value if isinstance(self.status, JobStatus) else self.status,
            "scan_paths": self.scan_paths,
            "exclude_patterns": self.exclude_patterns,
            "scanners": self.scanners,
            "priority": self.priority,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "findings_count": self.findings_count,
            "files_scanned": self.files_scanned,
            "error_message": self.error_message,
            "config": self.config
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ScanJob':
        return cls(
            job_id=data.get("job_id", ""),
            agent_id=data.get("agent_id"),
            job_type=JobType(data.get("job_type", "full_scan")),
            status=JobStatus(data.get("status", "pending")),
            scan_paths=data.get("scan_paths", []),
            exclude_patterns=data.get("exclude_patterns", []),
            scanners=data.get("scanners", ["custom", "trufflehog", "gitleaks"]),
            priority=data.get("priority", 5),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            assigned_at=datetime.fromisoformat(data["assigned_at"]) if data.get("assigned_at") else None,
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            findings_count=data.get("findings_count", 0),
            files_scanned=data.get("files_scanned", 0),
            error_message=data.get("error_message"),
            config=data.get("config", {})
        )


@dataclass
class Finding:
    """A security finding from a scan"""
    finding_id: str
    job_id: str
    agent_id: str
    file_path: str
    line_number: Optional[int] = None
    secret_type: str = ""
    secret_value: str = ""  # Will be masked
    context: str = ""
    severity: str = "Medium"
    confidence_score: float = 0.0
    tool_source: str = "custom"
    fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self._generate_fingerprint()
    
    def _generate_fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication"""
        content = f"{self.file_path}|{self.secret_type}|{self.secret_value}|{self.line_number or ''}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]
    
    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "job_id": self.job_id,
            "agent_id": self.agent_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "secret_type": self.secret_type,
            "secret_value": self.secret_value,
            "context": self.context,
            "severity": self.severity,
            "confidence_score": self.confidence_score,
            "tool_source": self.tool_source,
            "fingerprint": self.fingerprint,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Finding':
        return cls(
            finding_id=data.get("finding_id", str(uuid.uuid4())),
            job_id=data.get("job_id", ""),
            agent_id=data.get("agent_id", ""),
            file_path=data.get("file_path", ""),
            line_number=data.get("line_number"),
            secret_type=data.get("secret_type", ""),
            secret_value=data.get("secret_value", ""),
            context=data.get("context", ""),
            severity=data.get("severity", "Medium"),
            confidence_score=data.get("confidence_score", 0.0),
            tool_source=data.get("tool_source", "custom"),
            fingerprint=data.get("fingerprint", ""),
            metadata=data.get("metadata", {})
        )


@dataclass
class Heartbeat:
    """Agent heartbeat message"""
    agent_id: str
    timestamp: datetime
    status: AgentStatus
    current_job_id: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    scan_progress: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value if isinstance(self.status, AgentStatus) else self.status,
            "current_job_id": self.current_job_id,
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "disk_percent": self.disk_percent,
            "scan_progress": self.scan_progress
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Heartbeat':
        return cls(
            agent_id=data.get("agent_id", ""),
            timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else datetime.now(),
            status=AgentStatus(data.get("status", "online")),
            current_job_id=data.get("current_job_id"),
            cpu_percent=data.get("cpu_percent", 0.0),
            memory_percent=data.get("memory_percent", 0.0),
            disk_percent=data.get("disk_percent", 0.0),
            scan_progress=data.get("scan_progress")
        )


@dataclass 
class APIResponse:
    """Standard API response wrapper"""
    success: bool
    message: str
    data: Optional[Any] = None
    error_code: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "error_code": self.error_code
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
