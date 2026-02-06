"""
SecretSnipe Agent - Shared Configuration
"""

import os
from dataclasses import dataclass
from typing import Optional

# API Version
API_VERSION = "v1"

# Default ports
DEFAULT_AGENT_API_PORT = 8443
DEFAULT_AGENT_PORT = 8444

# Heartbeat settings
HEARTBEAT_INTERVAL_SECONDS = 30
HEARTBEAT_TIMEOUT_SECONDS = 90  # Agent considered offline after this

# Scan settings
DEFAULT_SCAN_TIMEOUT_SECONDS = 3600  # 1 hour max per job
MAX_FINDINGS_PER_BATCH = 100  # Send findings in batches

# Security settings
# Using 96 bytes generates a ~128 character base64 key for enterprise security
API_KEY_LENGTH = 96  # Increased from 64 for enhanced security
TOKEN_EXPIRY_HOURS = 24


@dataclass
class AgentConfig:
    """Configuration for the agent"""
    manager_url: str
    api_key: str
    agent_id: Optional[str] = None
    scan_paths: list = None
    exclude_patterns: list = None
    heartbeat_interval: int = HEARTBEAT_INTERVAL_SECONDS
    log_level: str = "INFO"
    verify_ssl: bool = True
    
    def __post_init__(self):
        if self.scan_paths is None:
            self.scan_paths = []
        if self.exclude_patterns is None:
            self.exclude_patterns = [
                "*.pyc", "__pycache__", ".git", "node_modules",
                "*.log", "*.tmp", ".venv", "venv"
            ]
    
    @classmethod
    def from_env(cls) -> 'AgentConfig':
        """Load configuration from environment variables"""
        return cls(
            manager_url=os.getenv("SECRETSNIPE_MANAGER_URL", "https://localhost:8443"),
            api_key=os.getenv("SECRETSNIPE_API_KEY", ""),
            agent_id=os.getenv("SECRETSNIPE_AGENT_ID"),
            scan_paths=os.getenv("SECRETSNIPE_SCAN_PATHS", "").split(",") if os.getenv("SECRETSNIPE_SCAN_PATHS") else [],
            heartbeat_interval=int(os.getenv("SECRETSNIPE_HEARTBEAT_INTERVAL", str(HEARTBEAT_INTERVAL_SECONDS))),
            log_level=os.getenv("SECRETSNIPE_LOG_LEVEL", "INFO"),
            verify_ssl=os.getenv("SECRETSNIPE_VERIFY_SSL", "true").lower() == "true"
        )


@dataclass
class ManagerConfig:
    """Configuration for the manager API"""
    host: str = "0.0.0.0"
    port: int = DEFAULT_AGENT_API_PORT
    database_url: str = ""
    redis_url: str = ""
    secret_key: str = ""
    ssl_cert: str = ""
    ssl_key: str = ""
    log_level: str = "INFO"
    
    @classmethod
    def from_env(cls) -> 'ManagerConfig':
        """Load configuration from environment variables"""
        return cls(
            host=os.getenv("AGENT_API_HOST", "0.0.0.0"),
            port=int(os.getenv("AGENT_API_PORT", str(DEFAULT_AGENT_API_PORT))),
            database_url=os.getenv("DATABASE_URL", "postgresql://secretsnipe:secretsnipe@localhost:5432/secretsnipe"),
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            secret_key=os.getenv("AGENT_API_SECRET_KEY", "change-me-in-production"),
            ssl_cert=os.getenv("AGENT_API_SSL_CERT", ""),
            ssl_key=os.getenv("AGENT_API_SSL_KEY", ""),
            log_level=os.getenv("AGENT_API_LOG_LEVEL", "INFO")
        )
