#!/usr/bin/env python3
"""
SecretSnipe Agent API - Management Server
FastAPI service for agent communication.

Endpoints:
- Agent registration
- Heartbeat processing
- Job assignment
- Findings submission
"""

import os
import sys
import json
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
import uvicorn

# Database
import psycopg2
from psycopg2.extras import RealDictCursor
import redis

# Add parent directory for shared imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import (
    AgentStatus, JobStatus, JobType,
    AgentInfo, ScanJob, Finding, Heartbeat, APIResponse
)
from shared.config import ManagerConfig, API_VERSION, HEARTBEAT_TIMEOUT_SECONDS, API_KEY_LENGTH

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("agent-api")


# ==================== Pydantic Models ====================

class AgentRegisterRequest(BaseModel):
    """Request model for agent registration"""
    agent_id: Optional[str] = None  # Optional - server will generate if not provided
    hostname: str
    ip_address: str
    os_type: str
    os_version: str
    agent_version: str
    scan_paths: List[str] = []
    capabilities: List[str] = []
    tags: List[str] = []
    metadata: Dict[str, Any] = {}


class HeartbeatRequest(BaseModel):
    """Request model for heartbeat"""
    agent_id: str
    timestamp: Optional[str] = None  # Optional - server will use current time
    status: str
    current_job_id: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    uptime_seconds: Optional[int] = None
    scan_progress: Optional[Dict[str, Any]] = None


class JobStatusUpdate(BaseModel):
    """Request model for job status update"""
    job_id: Optional[str] = None  # Optional - can be in URL or body
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    files_scanned: int = 0
    findings_count: int = 0
    error_message: Optional[str] = None


class FindingsSubmission(BaseModel):
    """Request model for findings submission"""
    job_id: Optional[str] = None  # Can be in URL or body
    agent_id: Optional[str] = None
    findings: List[Dict[str, Any]]


class CreateJobRequest(BaseModel):
    """Request model for creating a new scan job"""
    agent_id: Optional[str] = None
    job_type: str = "full_scan"
    scan_paths: List[str]
    exclude_patterns: List[str] = []
    scanners: List[str] = ["custom", "trufflehog", "gitleaks"]
    priority: int = 5
    config: Dict[str, Any] = {}


class CreateAPIKeyRequest(BaseModel):
    """Request model for creating API key"""
    name: str
    description: str = ""
    expires_days: int = 365


# ==================== Enterprise Models ====================

class LogEntry(BaseModel):
    """Single log entry"""
    timestamp: str
    level: str
    message: str
    context: Dict[str, Any] = {}


class LogsSubmission(BaseModel):
    """Request model for submitting logs"""
    logs: List[LogEntry]


class ScheduleRequest(BaseModel):
    """Request model for creating/updating schedules"""
    agent_id: Optional[str] = None  # Can be passed in body or as query param
    name: str
    scan_paths: List[str]
    cron_expression: str
    enabled: bool = True
    scanner_config: Dict[str, bool] = {"gitleaks": True, "trufflehog": True, "custom": True}


class ScheduleUpdate(BaseModel):
    """Request model for updating schedule"""
    name: Optional[str] = None
    scan_paths: Optional[List[str]] = None
    cron_expression: Optional[str] = None
    enabled: Optional[bool] = None
    scanner_config: Optional[Dict[str, bool]] = None
    last_run: Optional[str] = None


class WatchPathRequest(BaseModel):
    """Request model for watch paths"""
    path: str
    recursive: bool = True
    file_patterns: List[str] = ["*"]
    exclude_patterns: List[str] = ["node_modules", ".git", "__pycache__"]
    enabled: bool = True


class ConfigUpdate(BaseModel):
    """Request model for config update"""
    config: Dict[str, Any]


class FindingUpdate(BaseModel):
    """Request model for updating finding"""
    verified: Optional[bool] = None
    resolved: Optional[bool] = None
    resolved_by: Optional[str] = None


# ==================== Database Manager ====================

class AgentDatabaseManager:
    """Database manager for agent-related operations"""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self._init_tables()
    
    def _get_connection(self):
        """Get a database connection"""
        return psycopg2.connect(self.database_url, cursor_factory=RealDictCursor)
    
    def _init_tables(self):
        """Initialize agent tables if they don't exist"""
        create_sql = """
        -- API Keys table
        CREATE TABLE IF NOT EXISTS agent_api_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            key_hash VARCHAR(128) NOT NULL UNIQUE,
            key_prefix VARCHAR(8) NOT NULL,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            is_active BOOLEAN DEFAULT true,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            expires_at TIMESTAMP WITH TIME ZONE,
            last_used_at TIMESTAMP WITH TIME ZONE,
            created_by VARCHAR(255)
        );
        
        -- Agents table
        CREATE TABLE IF NOT EXISTS agents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            agent_id VARCHAR(64) NOT NULL UNIQUE,
            hostname VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45),
            os_type VARCHAR(50),
            os_version VARCHAR(255),
            agent_version VARCHAR(50),
            scan_paths TEXT[],
            capabilities TEXT[],
            status VARCHAR(50) DEFAULT 'pending',
            tags TEXT[],
            metadata JSONB DEFAULT '{}',
            registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_heartbeat TIMESTAMP WITH TIME ZONE,
            api_key_id UUID REFERENCES agent_api_keys(id)
        );
        
        -- Agent heartbeats history
        CREATE TABLE IF NOT EXISTS agent_heartbeats (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            agent_id VARCHAR(64) NOT NULL,
            timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
            status VARCHAR(50),
            current_job_id UUID,
            cpu_percent DECIMAL(5,2),
            memory_percent DECIMAL(5,2),
            disk_percent DECIMAL(5,2),
            scan_progress JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        
        -- Scan jobs table
        CREATE TABLE IF NOT EXISTS agent_jobs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id VARCHAR(64) NOT NULL UNIQUE,
            agent_id VARCHAR(64),
            job_type VARCHAR(50) DEFAULT 'full_scan',
            status VARCHAR(50) DEFAULT 'pending',
            scan_paths TEXT[],
            exclude_patterns TEXT[],
            scanners TEXT[],
            priority INTEGER DEFAULT 5,
            config JSONB DEFAULT '{}',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            assigned_at TIMESTAMP WITH TIME ZONE,
            started_at TIMESTAMP WITH TIME ZONE,
            completed_at TIMESTAMP WITH TIME ZONE,
            files_scanned INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            error_message TEXT
        );
        
        -- Agent commands table (for remote management)
        CREATE TABLE IF NOT EXISTS agent_commands (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            agent_id VARCHAR(64) NOT NULL,
            command VARCHAR(50) NOT NULL,
            parameters JSONB DEFAULT '{}',
            status VARCHAR(50) DEFAULT 'pending',
            result JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            completed_at TIMESTAMP WITH TIME ZONE
        );
        
        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
        CREATE INDEX IF NOT EXISTS idx_agents_last_heartbeat ON agents(last_heartbeat);
        CREATE INDEX IF NOT EXISTS idx_agent_jobs_status ON agent_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_agent_jobs_agent_id ON agent_jobs(agent_id);
        CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_agent_id ON agent_heartbeats(agent_id);
        CREATE INDEX IF NOT EXISTS idx_agent_api_keys_hash ON agent_api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_agent_commands_agent ON agent_commands(agent_id);
        CREATE INDEX IF NOT EXISTS idx_agent_commands_status ON agent_commands(status);
        """
        
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(create_sql)
                conn.commit()
            logger.info("Agent database tables initialized")
        except Exception as e:
            logger.error(f"Failed to initialize agent tables: {e}")
            raise
    
    # ========== API Key Operations ==========
    
    def create_api_key(self, name: str, description: str = "", expires_days: int = 365) -> tuple:
        """Create a new API key. Returns (key, key_id)"""
        key = secrets.token_urlsafe(API_KEY_LENGTH)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        key_prefix = key[:8]
        expires_at = datetime.now() + timedelta(days=expires_days)
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_api_keys (key_hash, key_prefix, name, description, expires_at)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (key_hash, key_prefix, name, description, expires_at))
                key_id = cur.fetchone()['id']
            conn.commit()
        
        return key, str(key_id)
    
    def validate_api_key(self, key: str) -> Optional[Dict]:
        """Validate an API key. Returns key info if valid, None if invalid."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, name, is_active, expires_at
                    FROM agent_api_keys
                    WHERE key_hash = %s
                """, (key_hash,))
                result = cur.fetchone()
                
                if not result:
                    return None
                
                if not result['is_active']:
                    return None
                
                if result['expires_at'] and result['expires_at'] < datetime.now():
                    return None
                
                # Update last used
                cur.execute("""
                    UPDATE agent_api_keys SET last_used_at = NOW() WHERE id = %s
                """, (result['id'],))
            conn.commit()
        
        return dict(result)
    
    def list_api_keys(self) -> List[Dict]:
        """List all API keys (without the actual key)"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, key_prefix, name, description, is_active, 
                           created_at, expires_at, last_used_at
                    FROM agent_api_keys
                    ORDER BY created_at DESC
                """)
                return [dict(row) for row in cur.fetchall()]
    
    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE agent_api_keys SET is_active = false WHERE id = %s
                """, (key_id,))
                affected = cur.rowcount
            conn.commit()
        return affected > 0
    
    # ========== Agent Operations ==========
    
    def register_agent(self, agent: AgentRegisterRequest) -> Dict:
        """Register a new agent or update existing based on hostname+IP fingerprint"""
        import uuid
        import hashlib
        
        # Create deterministic agent_id from hostname + IP (prevents duplicates on restart)
        fingerprint = f"{agent.hostname}:{agent.ip_address}"
        agent_id = agent.agent_id if agent.agent_id else str(uuid.uuid5(uuid.NAMESPACE_DNS, fingerprint))
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                # First check if an agent with same hostname+IP already exists
                cur.execute("""
                    SELECT agent_id FROM agents 
                    WHERE hostname = %s AND ip_address = %s
                """, (agent.hostname, agent.ip_address))
                existing = cur.fetchone()
                
                if existing:
                    # Use existing agent_id to update
                    agent_id = str(existing['agent_id'])
                
                cur.execute("""
                    INSERT INTO agents (agent_id, hostname, ip_address, os_type, os_version,
                                       agent_version, scan_paths, capabilities, status, metadata)
                    VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, 'online', %s)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        hostname = EXCLUDED.hostname,
                        ip_address = EXCLUDED.ip_address,
                        os_type = EXCLUDED.os_type,
                        os_version = EXCLUDED.os_version,
                        agent_version = EXCLUDED.agent_version,
                        scan_paths = EXCLUDED.scan_paths,
                        capabilities = EXCLUDED.capabilities,
                        status = 'online',
                        metadata = EXCLUDED.metadata,
                        last_heartbeat = NOW()
                    RETURNING id, agent_id, registered_at
                """, (
                    agent_id, agent.hostname, agent.ip_address,
                    agent.os_type, agent.os_version, agent.agent_version,
                    psycopg2.extras.Json(agent.scan_paths), 
                    psycopg2.extras.Json(agent.capabilities),
                    psycopg2.extras.Json(agent.metadata)
                ))
                result = cur.fetchone()
            conn.commit()
        return dict(result)
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent by ID"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM agents WHERE agent_id = %s", (agent_id,))
                result = cur.fetchone()
        return dict(result) if result else None
    
    def list_agents(self, status: str = None) -> List[Dict]:
        """List all agents, optionally filtered by status"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                if status:
                    cur.execute("SELECT * FROM agents WHERE status = %s ORDER BY hostname", (status,))
                else:
                    cur.execute("SELECT * FROM agents ORDER BY hostname")
                return [dict(row) for row in cur.fetchall()]
    
    def update_agent_heartbeat(self, heartbeat: HeartbeatRequest) -> bool:
        """Update agent heartbeat"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                # Update agent status
                cur.execute("""
                    UPDATE agents 
                    SET status = %s, last_heartbeat = NOW()
                    WHERE agent_id = %s::uuid
                """, (heartbeat.status, heartbeat.agent_id))
                
                # Insert heartbeat record (matches actual table schema)
                cur.execute("""
                    INSERT INTO agent_heartbeats 
                    (agent_id, status, cpu_percent, memory_percent, disk_percent, uptime_seconds)
                    VALUES (%s::uuid, %s, %s, %s, %s, %s)
                """, (
                    heartbeat.agent_id, heartbeat.status,
                    heartbeat.cpu_percent, heartbeat.memory_percent,
                    heartbeat.disk_percent, heartbeat.uptime_seconds
                ))
            conn.commit()
        return True
    
    def update_offline_agents(self):
        """Mark agents as offline if no heartbeat received"""
        threshold = datetime.now() - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS)
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE agents SET status = 'offline'
                    WHERE status != 'offline' AND last_heartbeat < %s
                """, (threshold,))
                affected = cur.rowcount
            conn.commit()
        if affected:
            logger.info(f"Marked {affected} agents as offline")
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM agents WHERE agent_id = %s", (agent_id,))
                affected = cur.rowcount
            conn.commit()
        return affected > 0
    
    # ========== Job Operations ==========
    
    def create_job(self, job: CreateJobRequest) -> Dict:
        """Create a new scan job"""
        import uuid
        job_id = str(uuid.uuid4())  # Full UUID for database
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_jobs 
                    (job_id, agent_id, job_type, scan_paths, scanners, priority, config)
                    VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s)
                    RETURNING *
                """, (
                    job_id, job.agent_id if job.agent_id else None, job.job_type, 
                    psycopg2.extras.Json(job.scan_paths),
                    psycopg2.extras.Json(job.scanners), job.priority,
                    psycopg2.extras.Json(job.config)
                ))
                result = cur.fetchone()
            conn.commit()
        return dict(result)
    
    def get_job(self, job_id: str) -> Optional[Dict]:
        """Get job by ID"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM agent_jobs WHERE job_id = %s::uuid", (job_id,))
                result = cur.fetchone()
        return dict(result) if result else None
    
    def get_pending_job_for_agent(self, agent_id: str) -> Optional[Dict]:
        """Get the next pending job for an agent"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                # First check for jobs assigned to this specific agent
                cur.execute("""
                    SELECT * FROM agent_jobs 
                    WHERE agent_id = %s::uuid AND status = 'pending'
                    ORDER BY priority DESC, created_at ASC
                    LIMIT 1
                """, (agent_id,))
                result = cur.fetchone()
                
                if not result:
                    # Check for unassigned jobs
                    cur.execute("""
                        SELECT * FROM agent_jobs 
                        WHERE agent_id IS NULL AND status = 'pending'
                        ORDER BY priority DESC, created_at ASC
                        LIMIT 1
                    """)
                    result = cur.fetchone()
                
                if result:
                    # Assign job to agent
                    cur.execute("""
                        UPDATE agent_jobs 
                        SET agent_id = %s::uuid, status = 'assigned', assigned_at = NOW()
                        WHERE job_id = %s
                    """, (agent_id, result['job_id']))
                    conn.commit()
                    result = dict(result)
                    result['agent_id'] = agent_id
                    result['status'] = 'assigned'
        
        return result
    
    def update_job_status(self, job_id: str, update: JobStatusUpdate) -> bool:
        """Update job status"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                updates = ["status = %s"]
                values = [update.status]
                
                if update.started_at:
                    updates.append("started_at = %s")
                    values.append(update.started_at)
                if update.completed_at:
                    updates.append("completed_at = %s")
                    values.append(update.completed_at)
                if update.files_scanned:
                    updates.append("files_scanned = %s")
                    values.append(update.files_scanned)
                if update.findings_count:
                    updates.append("findings_count = %s")
                    values.append(update.findings_count)
                if update.error_message:
                    updates.append("error_message = %s")
                    values.append(update.error_message)
                
                values.append(job_id)
                cur.execute(f"""
                    UPDATE agent_jobs SET {', '.join(updates)} WHERE job_id = %s
                """, values)
            conn.commit()
        return True
    
    def list_jobs(self, status: str = None, agent_id: str = None, limit: int = 100) -> List[Dict]:
        """List jobs with optional filters"""
        conditions = []
        values = []
        
        if status:
            conditions.append("status = %s")
            values.append(status)
        if agent_id:
            conditions.append("agent_id = %s")
            values.append(agent_id)
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    SELECT * FROM agent_jobs {where_clause}
                    ORDER BY created_at DESC LIMIT %s
                """, values + [limit])
                return [dict(row) for row in cur.fetchall()]
    
    # ========== Findings Operations ==========
    
    def submit_findings(self, job_id: str, findings: List[Dict]) -> int:
        """Submit findings from agent to agent_findings table"""
        inserted = 0
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                for finding in findings:
                    try:
                        # Generate a fingerprint from the finding details
                        import hashlib
                        fingerprint_data = f"{finding.get('file_path')}:{finding.get('line_number')}:{finding.get('secret_type')}:{finding.get('secret_value', '')[:20]}"
                        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
                        
                        cur.execute("""
                            INSERT INTO agent_findings 
                            (job_id, agent_id, secret_type, secret_value, file_path, line_number,
                             line_content, scanner, pattern_name, severity, fingerprint)
                            VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (fingerprint) DO NOTHING
                        """, (
                            job_id,
                            finding.get('agent_id'),
                            finding.get('secret_type'),
                            finding.get('secret_value', '')[:500],  # Truncate
                            finding.get('file_path'),
                            finding.get('line_number'),
                            finding.get('line_content', '')[:1000],  # Truncate
                            finding.get('scanner', 'custom'),
                            finding.get('pattern_name'),
                            finding.get('severity', 'medium'),
                            fingerprint
                        ))
                        if cur.rowcount > 0:
                            inserted += 1
                    except Exception as e:
                        logger.error(f"Failed to insert finding: {e}")
            conn.commit()
        
        return inserted
    
    # ========== Enterprise: Logs Operations ==========
    
    def submit_agent_logs(self, agent_id: str, logs: List[Dict]) -> int:
        """Submit logs from agent"""
        inserted = 0
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                for log in logs:
                    try:
                        cur.execute("""
                            INSERT INTO agent_logs (agent_id, timestamp, level, message, context)
                            VALUES (%s::uuid, %s, %s, %s, %s)
                        """, (
                            agent_id,
                            log.get('timestamp', datetime.utcnow().isoformat()),
                            log.get('level', 'INFO'),
                            log.get('message', ''),
                            psycopg2.extras.Json(log.get('context', {}))
                        ))
                        inserted += 1
                    except Exception as e:
                        logger.debug(f"Failed to insert log: {e}")
                conn.commit()
        return inserted
    
    def get_agent_logs(self, agent_id: str, lines: int = 100, level: str = None) -> List[Dict]:
        """Get agent logs"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                query = """
                    SELECT timestamp, level, message, context 
                    FROM agent_logs 
                    WHERE agent_id = %s::uuid
                """
                params = [agent_id]
                
                if level:
                    query += " AND level = %s"
                    params.append(level)
                
                query += " ORDER BY timestamp DESC LIMIT %s"
                params.append(lines)
                
                cur.execute(query, params)
                return [dict(row) for row in cur.fetchall()]
    
    # ========== Enterprise: Schedule Operations ==========
    
    def create_schedule(self, agent_id: str, schedule: Dict) -> Dict:
        """Create a scan schedule"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scan_schedules 
                    (agent_id, name, scan_paths, cron_expression, enabled, scanner_config)
                    VALUES (%s::uuid, %s, %s, %s, %s, %s)
                    RETURNING schedule_id, name, scan_paths, cron_expression, enabled, scanner_config, created_at
                """, (
                    agent_id,
                    schedule['name'],
                    psycopg2.extras.Json(schedule['scan_paths']),  # JSONB column
                    schedule['cron_expression'],
                    schedule.get('enabled', True),
                    psycopg2.extras.Json(schedule.get('scanner_config', {}))
                ))
                result = dict(cur.fetchone())
                conn.commit()
                return result
    
    def get_schedules(self, agent_id: str = None) -> List[Dict]:
        """Get schedules, optionally filtered by agent"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                if agent_id:
                    cur.execute("""
                        SELECT s.*, a.hostname as agent_hostname
                        FROM scan_schedules s
                        LEFT JOIN agents a ON s.agent_id = a.agent_id::uuid
                        WHERE s.agent_id = %s::uuid
                        ORDER BY s.created_at DESC
                    """, (agent_id,))
                else:
                    cur.execute("""
                        SELECT s.*, a.hostname as agent_hostname
                        FROM scan_schedules s
                        LEFT JOIN agents a ON s.agent_id = a.agent_id::uuid
                        ORDER BY s.created_at DESC
                    """)
                return [dict(row) for row in cur.fetchall()]
    
    def update_schedule(self, schedule_id: str, updates: Dict) -> bool:
        """Update a schedule"""
        set_clauses = []
        values = []
        
        if 'name' in updates and updates['name']:
            set_clauses.append("name = %s")
            values.append(updates['name'])
        if 'scan_paths' in updates and updates['scan_paths']:
            set_clauses.append("scan_paths = %s")
            values.append(psycopg2.extras.Json(updates['scan_paths']))  # JSONB column
        if 'cron_expression' in updates and updates['cron_expression']:
            set_clauses.append("cron_expression = %s")
            values.append(updates['cron_expression'])
        if 'enabled' in updates and updates['enabled'] is not None:
            set_clauses.append("enabled = %s")
            values.append(updates['enabled'])
        if 'scanner_config' in updates and updates['scanner_config']:
            set_clauses.append("scanner_config = %s")
            values.append(psycopg2.extras.Json(updates['scanner_config']))
        if 'last_run' in updates and updates['last_run']:
            set_clauses.append("last_run = %s")
            values.append(updates['last_run'])
        
        if not set_clauses:
            return False
        
        set_clauses.append("updated_at = NOW()")
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    UPDATE scan_schedules 
                    SET {', '.join(set_clauses)}
                    WHERE schedule_id = %s::uuid
                """, values + [schedule_id])
                conn.commit()
                return cur.rowcount > 0
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scan_schedules WHERE schedule_id = %s::uuid", (schedule_id,))
                conn.commit()
                return cur.rowcount > 0
    
    # ========== Enterprise: Watch Paths Operations ==========
    
    def get_watch_paths(self, agent_id: str) -> List[Dict]:
        """Get watch paths for an agent"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, path, recursive, file_patterns, exclude_patterns, enabled, created_at
                    FROM agent_watch_paths
                    WHERE agent_id = %s::uuid AND enabled = true
                    ORDER BY created_at
                """, (agent_id,))
                return [dict(row) for row in cur.fetchall()]
    
    def add_watch_path(self, agent_id: str, watch_path: Dict) -> Dict:
        """Add a watch path for an agent"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_watch_paths 
                    (agent_id, path, recursive, file_patterns, exclude_patterns, enabled)
                    VALUES (%s::uuid, %s, %s, %s, %s, %s)
                    ON CONFLICT (agent_id, path) DO UPDATE SET
                        recursive = EXCLUDED.recursive,
                        file_patterns = EXCLUDED.file_patterns,
                        exclude_patterns = EXCLUDED.exclude_patterns,
                        enabled = EXCLUDED.enabled
                    RETURNING id, path, recursive, file_patterns, exclude_patterns, enabled
                """, (
                    agent_id,
                    watch_path['path'],
                    watch_path.get('recursive', True),
                    psycopg2.extras.Json(watch_path.get('file_patterns', ['*'])),
                    psycopg2.extras.Json(watch_path.get('exclude_patterns', [])),
                    watch_path.get('enabled', True)
                ))
                result = dict(cur.fetchone())
                conn.commit()
                return result
    
    def delete_watch_path(self, agent_id: str, path_id: int) -> bool:
        """Delete a watch path"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM agent_watch_paths 
                    WHERE id = %s AND agent_id = %s::uuid
                """, (path_id, agent_id))
                conn.commit()
                return cur.rowcount > 0
    
    # ========== Enterprise: Config Operations ==========
    
    def get_agent_config(self, agent_id: str) -> Optional[Dict]:
        """Get agent configuration"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT config, version, updated_at
                    FROM agent_configs
                    WHERE agent_id = %s::uuid
                """, (agent_id,))
                result = cur.fetchone()
                return dict(result) if result else None
    
    def set_agent_config(self, agent_id: str, config: Dict) -> Dict:
        """Set/update agent configuration"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_configs (agent_id, config, version)
                    VALUES (%s::uuid, %s, 1)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        config = EXCLUDED.config,
                        version = agent_configs.version + 1,
                        updated_at = NOW()
                    RETURNING config_id, config, version, updated_at
                """, (agent_id, psycopg2.extras.Json(config)))
                result = dict(cur.fetchone())
                conn.commit()
                
                # Update agent's config version
                cur.execute("""
                    UPDATE agents SET config_version = %s WHERE agent_id = %s
                """, (result['version'], agent_id))
                conn.commit()
                
                return result
    
    # ========== Enterprise: Findings Operations ==========
    
    def get_findings(self, agent_id: str = None, job_id: str = None, 
                     severity: str = None, resolved: bool = None, limit: int = 100) -> List[Dict]:
        """Get findings with filters"""
        conditions = []
        values = []
        
        if agent_id:
            conditions.append("agent_id = %s::uuid")
            values.append(agent_id)
        if job_id:
            conditions.append("job_id = %s::uuid")
            values.append(job_id)
        if severity:
            conditions.append("severity = %s")
            values.append(severity)
        if resolved is not None:
            conditions.append("resolved = %s")
            values.append(resolved)
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    SELECT * FROM agent_findings 
                    {where_clause}
                    ORDER BY found_at DESC LIMIT %s
                """, values + [limit])
                return [dict(row) for row in cur.fetchall()]
    
    def update_finding(self, finding_id: str, updates: Dict) -> bool:
        """Update a finding (verify, resolve, etc.)"""
        set_clauses = []
        values = []
        
        if 'verified' in updates:
            set_clauses.append("verified = %s")
            values.append(updates['verified'])
        if 'resolved' in updates:
            set_clauses.append("resolved = %s")
            values.append(updates['resolved'])
            if updates['resolved']:
                set_clauses.append("resolved_at = NOW()")
        if 'resolved_by' in updates:
            set_clauses.append("resolved_by = %s")
            values.append(updates['resolved_by'])
        
        if not set_clauses:
            return False
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    UPDATE agent_findings 
                    SET {', '.join(set_clauses)}
                    WHERE id = %s::uuid
                """, values + [finding_id])
                conn.commit()
                return cur.rowcount > 0
    
    def get_agent_stats(self) -> Dict:
        """Get overall agent statistics"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                stats = {}
                
                # Agent counts by status
                cur.execute("""
                    SELECT status, COUNT(*) as count FROM agents GROUP BY status
                """)
                stats['agents_by_status'] = {row['status']: row['count'] for row in cur.fetchall()}
                
                # Total agents
                cur.execute("SELECT COUNT(*) as total FROM agents")
                stats['total_agents'] = cur.fetchone()['total']
                
                # Job counts by status
                cur.execute("""
                    SELECT status, COUNT(*) as count FROM agent_jobs GROUP BY status
                """)
                stats['jobs_by_status'] = {row['status']: row['count'] for row in cur.fetchall()}
                
                # Recent job activity
                cur.execute("""
                    SELECT COUNT(*) as count FROM agent_jobs 
                    WHERE created_at > NOW() - INTERVAL '24 hours'
                """)
                stats['jobs_last_24h'] = cur.fetchone()['count']
                
                # Total findings from agents
                cur.execute("""
                    SELECT SUM(findings_count) as total FROM agent_jobs WHERE status = 'completed'
                """)
                result = cur.fetchone()
                stats['total_findings'] = result['total'] or 0
        
        return stats
    
    # ========== Agent Command Operations ==========
    
    def queue_agent_command(self, agent_id: str, command: str, parameters: Dict = None) -> Optional[str]:
        """Queue a command for an agent to execute"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                # Verify agent exists
                cur.execute("SELECT agent_id FROM agents WHERE agent_id = %s", (agent_id,))
                if not cur.fetchone():
                    return None
                
                cur.execute("""
                    INSERT INTO agent_commands (agent_id, command, parameters, status)
                    VALUES (%s, %s, %s, 'pending')
                    RETURNING id
                """, (agent_id, command, json.dumps(parameters or {})))
                result = cur.fetchone()
                conn.commit()
                return str(result['id']) if result else None
    
    def get_pending_commands(self, agent_id: str) -> List[Dict]:
        """Get pending commands for an agent"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, command, parameters, created_at
                    FROM agent_commands
                    WHERE agent_id = %s AND status = 'pending'
                    ORDER BY created_at ASC
                """, (agent_id,))
                return [dict(row) for row in cur.fetchall()]
    
    def complete_command(self, command_id: str, result: Dict = None):
        """Mark a command as completed with result"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE agent_commands 
                    SET status = 'completed', completed_at = NOW(), result = %s
                    WHERE id = %s::uuid
                """, (json.dumps(result or {}), command_id))
                conn.commit()
    
    def get_agent_paths(self, agent_id: str) -> List[Dict]:
        """Get available paths from an agent (from command results)"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT result FROM agent_commands
                    WHERE agent_id = %s AND command = 'list_paths' AND status = 'completed'
                    ORDER BY completed_at DESC
                    LIMIT 1
                """, (agent_id,))
                result = cur.fetchone()
                if result and result['result']:
                    paths_data = result['result'] if isinstance(result['result'], dict) else json.loads(result['result'])
                    return paths_data.get('paths', [])
                return []
    
    # ========== Enhanced API Key Operations ==========
    
    def update_api_key(self, key_id: str, updates: Dict) -> bool:
        """Update API key properties"""
        set_clauses = []
        values = []
        
        if 'name' in updates:
            set_clauses.append("name = %s")
            values.append(updates['name'])
        if 'description' in updates:
            set_clauses.append("description = %s")
            values.append(updates['description'])
        if 'expires_at' in updates:
            set_clauses.append("expires_at = %s")
            values.append(updates['expires_at'])
        if 'is_active' in updates:
            set_clauses.append("is_active = %s")
            values.append(updates['is_active'])
        
        if not set_clauses:
            return False
        
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    UPDATE agent_api_keys 
                    SET {', '.join(set_clauses)}
                    WHERE id = %s::uuid
                """, values + [key_id])
                conn.commit()
                return cur.rowcount > 0
    
    def get_api_key_usage(self, key_id: str, days: int = 30) -> Dict:
        """Get API key usage statistics"""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                # Get key info
                cur.execute("""
                    SELECT name, created_at, last_used_at, expires_at, is_active
                    FROM agent_api_keys WHERE id = %s::uuid
                """, (key_id,))
                key_info = cur.fetchone()
                if not key_info:
                    return {}
                
                # Count agents using this key
                cur.execute("""
                    SELECT COUNT(*) as count FROM agents WHERE api_key_id = %s::uuid
                """, (key_id,))
                agents_count = cur.fetchone()['count']
                
                return {
                    'name': key_info['name'],
                    'created_at': str(key_info['created_at']),
                    'last_used_at': str(key_info['last_used_at']) if key_info['last_used_at'] else None,
                    'expires_at': str(key_info['expires_at']) if key_info['expires_at'] else None,
                    'is_active': key_info['is_active'],
                    'agents_using_key': agents_count
                }


# ==================== API Application ====================

# Global database manager
db_manager: Optional[AgentDatabaseManager] = None
config: Optional[ManagerConfig] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    global db_manager, config
    
    config = ManagerConfig.from_env()
    db_manager = AgentDatabaseManager(config.database_url)
    logger.info("Agent API initialized")
    
    yield
    
    logger.info("Agent API shutting down")


app = FastAPI(
    title="SecretSnipe Agent API",
    description="API for SecretSnipe agent communication",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Depends(api_key_header)) -> Dict:
    """Verify API key and return key info"""
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    key_info = db_manager.validate_api_key(api_key)
    if not key_info:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")
    
    return key_info


# ==================== API Endpoints ====================

@app.get(f"/api/{API_VERSION}/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# ========== API Key Management ==========

@app.post(f"/api/{API_VERSION}/keys")
async def create_api_key(request: CreateAPIKeyRequest, key_info: Dict = Depends(verify_api_key)):
    """Create a new API key (requires existing key)"""
    key, key_id = db_manager.create_api_key(request.name, request.description, request.expires_days)
    return APIResponse(
        success=True,
        message="API key created",
        data={"api_key": key, "key_id": key_id}
    ).to_dict()


@app.get(f"/api/{API_VERSION}/keys")
async def list_api_keys(key_info: Dict = Depends(verify_api_key)):
    """List all API keys"""
    keys = db_manager.list_api_keys()
    return APIResponse(success=True, message="OK", data=keys).to_dict()


@app.delete(f"/api/{API_VERSION}/keys/{{key_id}}")
async def revoke_api_key(key_id: str, key_info: Dict = Depends(verify_api_key)):
    """Revoke an API key"""
    if db_manager.revoke_api_key(key_id):
        return APIResponse(success=True, message="API key revoked").to_dict()
    raise HTTPException(status_code=404, detail="API key not found")


# ========== Agent Download Endpoints ==========

@app.get(f"/api/{API_VERSION}/agent/download")
async def download_agent_script():
    """Download the agent Python script - public endpoint (no auth required)"""
    from fastapi.responses import FileResponse
    
    # Look for agent script in various locations
    script_locations = [
        Path(__file__).parent.parent / "windows_installer" / "secretsnipe_enterprise_agent.py",
        Path(__file__).parent / "secretsnipe_enterprise_agent.py",
        Path("/app/agent_project/windows_installer/secretsnipe_enterprise_agent.py"),
        Path("/app/secretsnipe_enterprise_agent.py"),
    ]
    
    for script_path in script_locations:
        if script_path.exists():
            logger.info(f"Serving agent script from {script_path}")
            return FileResponse(
                path=str(script_path),
                filename="secretsnipe_agent.py",
                media_type="text/x-python"
            )
    
    logger.error("Agent script not found in any expected location")
    raise HTTPException(status_code=404, detail="Agent script not found")


# ========== Agent Endpoints ==========

@app.post(f"/api/{API_VERSION}/agents/register")
async def register_agent(request: AgentRegisterRequest, key_info: Dict = Depends(verify_api_key)):
    """Register a new agent"""
    result = db_manager.register_agent(request)
    logger.info(f"Agent registered: {request.agent_id} ({request.hostname})")
    return APIResponse(
        success=True,
        message="Agent registered",
        data={"agent_id": result['agent_id'], "registered_at": str(result['registered_at'])}
    ).to_dict()


@app.post(f"/api/{API_VERSION}/agents/heartbeat")
async def agent_heartbeat(request: HeartbeatRequest, key_info: Dict = Depends(verify_api_key)):
    """Receive agent heartbeat"""
    db_manager.update_agent_heartbeat(request)
    return APIResponse(success=True, message="Heartbeat received").to_dict()


@app.get(f"/api/{API_VERSION}/agents")
async def list_agents(status: Optional[str] = None, key_info: Dict = Depends(verify_api_key)):
    """List all agents"""
    agents = db_manager.list_agents(status)
    return APIResponse(success=True, message="OK", data=agents).to_dict()


@app.get(f"/api/{API_VERSION}/agents/{{agent_id}}")
async def get_agent(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Get agent details"""
    agent = db_manager.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return APIResponse(success=True, message="OK", data=agent).to_dict()


@app.delete(f"/api/{API_VERSION}/agents/{{agent_id}}")
async def delete_agent(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Delete an agent"""
    if db_manager.delete_agent(agent_id):
        return APIResponse(success=True, message="Agent deleted").to_dict()
    raise HTTPException(status_code=404, detail="Agent not found")


@app.get(f"/api/{API_VERSION}/agents/{{agent_id}}/jobs")
async def get_agent_job(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Get pending job for agent"""
    job = db_manager.get_pending_job_for_agent(agent_id)
    return APIResponse(success=True, message="OK", data=job).to_dict()


# ========== Job Endpoints ==========

@app.get(f"/api/{API_VERSION}/jobs/poll")
async def poll_for_job(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Poll for pending job for an agent (must be defined before /jobs/{job_id})"""
    job = db_manager.get_pending_job_for_agent(agent_id)
    return APIResponse(success=True, message="OK", data=job).to_dict()


@app.post(f"/api/{API_VERSION}/jobs")
async def create_job(request: CreateJobRequest, key_info: Dict = Depends(verify_api_key)):
    """Create a new scan job"""
    job = db_manager.create_job(request)
    logger.info(f"Job created: {job['job_id']}")
    return APIResponse(success=True, message="Job created", data=job).to_dict()


@app.get(f"/api/{API_VERSION}/jobs")
async def list_jobs(
    status: Optional[str] = None, 
    agent_id: Optional[str] = None,
    limit: int = 100,
    key_info: Dict = Depends(verify_api_key)
):
    """List jobs"""
    jobs = db_manager.list_jobs(status, agent_id, limit)
    return APIResponse(success=True, message="OK", data=jobs).to_dict()


@app.get(f"/api/{API_VERSION}/jobs/{{job_id}}")
async def get_job(job_id: str, key_info: Dict = Depends(verify_api_key)):
    """Get job details"""
    job = db_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return APIResponse(success=True, message="OK", data=job).to_dict()


@app.post(f"/api/{API_VERSION}/jobs/{{job_id}}/status")
async def update_job_status(job_id: str, request: JobStatusUpdate, key_info: Dict = Depends(verify_api_key)):
    """Update job status"""
    db_manager.update_job_status(job_id, request)
    logger.info(f"Job {job_id} status updated to {request.status}")
    return APIResponse(success=True, message="Status updated").to_dict()


@app.post(f"/api/{API_VERSION}/jobs/status")
async def update_job_status_alt(request: JobStatusUpdate, key_info: Dict = Depends(verify_api_key)):
    """Update job status (alternative endpoint with job_id in body)"""
    if not request.job_id:
        raise HTTPException(status_code=400, detail="job_id is required")
    db_manager.update_job_status(request.job_id, request)
    logger.info(f"Job {request.job_id} status updated to {request.status}")
    return APIResponse(success=True, message="Status updated").to_dict()


@app.post(f"/api/{API_VERSION}/jobs/{{job_id}}/findings")
async def submit_findings(job_id: str, request: FindingsSubmission, key_info: Dict = Depends(verify_api_key)):
    """Submit findings for a job"""
    count = db_manager.submit_findings(job_id, request.findings)
    logger.info(f"Received {len(request.findings)} findings for job {job_id}, inserted {count}")
    return APIResponse(
        success=True, 
        message="Findings received",
        data={"submitted": len(request.findings), "inserted": count}
    ).to_dict()


@app.post(f"/api/{API_VERSION}/findings/submit")
async def submit_findings_alt(request: FindingsSubmission, key_info: Dict = Depends(verify_api_key)):
    """Submit findings (alternative endpoint with job_id in body)"""
    if not request.job_id:
        raise HTTPException(status_code=400, detail="job_id is required")
    count = db_manager.submit_findings(request.job_id, request.findings)
    logger.info(f"Received {len(request.findings)} findings for job {request.job_id}, inserted {count}")
    return APIResponse(
        success=True, 
        message="Findings received",
        data={"submitted": len(request.findings), "inserted": count}
    ).to_dict()


# ========== Stats Endpoints ==========

@app.get(f"/api/{API_VERSION}/stats")
async def get_stats(key_info: Dict = Depends(verify_api_key)):
    """Get agent statistics"""
    stats = db_manager.get_agent_stats()
    return APIResponse(success=True, message="OK", data=stats).to_dict()


# ==================== Enterprise Endpoints ====================

# ========== Logs Endpoints ==========

@app.post(f"/api/{API_VERSION}/agents/{{agent_id}}/logs")
async def submit_agent_logs(agent_id: str, request: LogsSubmission, key_info: Dict = Depends(verify_api_key)):
    """Submit logs from agent"""
    count = db_manager.submit_agent_logs(agent_id, [log.dict() for log in request.logs])
    return APIResponse(success=True, message="Logs received", data={"count": count}).to_dict()


@app.get(f"/api/{API_VERSION}/agents/{{agent_id}}/logs")
async def get_agent_logs(
    agent_id: str,
    lines: int = 100,
    level: Optional[str] = None,
    key_info: Dict = Depends(verify_api_key)
):
    """Get agent logs"""
    logs = db_manager.get_agent_logs(agent_id, lines, level)
    return APIResponse(success=True, message="OK", data=logs).to_dict()


# ========== Schedule Endpoints ==========

@app.get(f"/api/{API_VERSION}/schedules")
async def list_schedules(key_info: Dict = Depends(verify_api_key)):
    """List all schedules"""
    schedules = db_manager.get_schedules()
    return APIResponse(success=True, message="OK", data=schedules).to_dict()


@app.post(f"/api/{API_VERSION}/schedules")
async def create_schedule(
    request: ScheduleRequest,
    agent_id: Optional[str] = None,
    key_info: Dict = Depends(verify_api_key)
):
    """Create a new schedule"""
    # Use agent_id from request body if not provided as query param
    actual_agent_id = agent_id or request.agent_id
    if not actual_agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required (either in body or query param)")
    schedule = db_manager.create_schedule(actual_agent_id, request.dict(exclude={'agent_id'}))
    return APIResponse(success=True, message="Schedule created", data=schedule).to_dict()


@app.get(f"/api/{API_VERSION}/agents/{{agent_id}}/schedules")
async def get_agent_schedules(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Get schedules for an agent"""
    schedules = db_manager.get_schedules(agent_id)
    return APIResponse(success=True, message="OK", data=schedules).to_dict()


@app.put(f"/api/{API_VERSION}/schedules/{{schedule_id}}")
async def update_schedule(schedule_id: str, request: ScheduleUpdate, key_info: Dict = Depends(verify_api_key)):
    """Update a schedule"""
    success = db_manager.update_schedule(schedule_id, request.dict(exclude_none=True))
    if not success:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return APIResponse(success=True, message="Schedule updated").to_dict()


@app.delete(f"/api/{API_VERSION}/schedules/{{schedule_id}}")
async def delete_schedule(schedule_id: str, key_info: Dict = Depends(verify_api_key)):
    """Delete a schedule"""
    success = db_manager.delete_schedule(schedule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return APIResponse(success=True, message="Schedule deleted").to_dict()


# ========== Watch Paths Endpoints ==========

@app.get(f"/api/{API_VERSION}/agents/{{agent_id}}/watch-paths")
async def get_watch_paths(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Get watch paths for an agent"""
    paths = db_manager.get_watch_paths(agent_id)
    return APIResponse(success=True, message="OK", data=paths).to_dict()


@app.post(f"/api/{API_VERSION}/agents/{{agent_id}}/watch-paths")
async def add_watch_path(agent_id: str, request: WatchPathRequest, key_info: Dict = Depends(verify_api_key)):
    """Add a watch path for an agent"""
    path = db_manager.add_watch_path(agent_id, request.dict())
    return APIResponse(success=True, message="Watch path added", data=path).to_dict()


@app.delete(f"/api/{API_VERSION}/agents/{{agent_id}}/watch-paths/{{path_id}}")
async def delete_watch_path(agent_id: str, path_id: int, key_info: Dict = Depends(verify_api_key)):
    """Delete a watch path"""
    success = db_manager.delete_watch_path(agent_id, path_id)
    if not success:
        raise HTTPException(status_code=404, detail="Watch path not found")
    return APIResponse(success=True, message="Watch path deleted").to_dict()


# ========== Config Endpoints ==========

@app.get(f"/api/{API_VERSION}/agents/{{agent_id}}/config")
async def get_agent_config(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Get agent configuration"""
    config = db_manager.get_agent_config(agent_id)
    return APIResponse(success=True, message="OK", data=config).to_dict()


@app.put(f"/api/{API_VERSION}/agents/{{agent_id}}/config")
async def set_agent_config(agent_id: str, request: ConfigUpdate, key_info: Dict = Depends(verify_api_key)):
    """Set/update agent configuration"""
    result = db_manager.set_agent_config(agent_id, request.config)
    return APIResponse(success=True, message="Config updated", data=result).to_dict()


# ========== Findings Endpoints ==========

@app.get(f"/api/{API_VERSION}/findings")
async def get_findings(
    agent_id: Optional[str] = None,
    job_id: Optional[str] = None,
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    limit: int = 100,
    key_info: Dict = Depends(verify_api_key)
):
    """Get findings with filters"""
    findings = db_manager.get_findings(agent_id, job_id, severity, resolved, limit)
    return APIResponse(success=True, message="OK", data=findings).to_dict()


@app.put(f"/api/{API_VERSION}/findings/{{finding_id}}")
async def update_finding(finding_id: str, request: FindingUpdate, key_info: Dict = Depends(verify_api_key)):
    """Update a finding (verify, resolve)"""
    success = db_manager.update_finding(finding_id, request.dict(exclude_none=True))
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")
    return APIResponse(success=True, message="Finding updated").to_dict()


# ==================== Agent Commands ====================

class AgentCommand(BaseModel):
    """Request model for sending commands to agents"""
    command: str  # update, restart, list_paths, fetch_config
    parameters: Dict[str, Any] = {}


class CommandResult(BaseModel):
    """Request model for command completion result"""
    result: Dict[str, Any] = {}


@app.post(f"/api/{API_VERSION}/agents/{{agent_id}}/command")
async def send_agent_command(agent_id: str, request: AgentCommand, key_info: Dict = Depends(verify_api_key)):
    """Send a command to an agent (will be picked up on next heartbeat)"""
    valid_commands = ['update', 'restart', 'list_paths', 'fetch_config', 'clear_cache']
    if request.command not in valid_commands:
        raise HTTPException(status_code=400, detail=f"Invalid command. Valid: {valid_commands}")
    
    # Store command for agent to pick up
    command_id = db_manager.queue_agent_command(agent_id, request.command, request.parameters)
    if not command_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return APIResponse(
        success=True,
        message=f"Command '{request.command}' queued for agent",
        data={"command_id": command_id, "command": request.command}
    ).to_dict()


@app.get(f"/api/{API_VERSION}/agents/{{agent_id}}/commands")
async def get_pending_commands(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Get pending commands for an agent (called by agent during heartbeat)"""
    commands = db_manager.get_pending_commands(agent_id)
    return APIResponse(success=True, message="OK", data=commands).to_dict()


@app.post(f"/api/{API_VERSION}/agents/{{agent_id}}/commands/{{command_id}}/complete")
async def complete_command(agent_id: str, command_id: str, body: CommandResult = CommandResult(), key_info: Dict = Depends(verify_api_key)):
    """Mark a command as completed and store result"""
    db_manager.complete_command(command_id, body.result)
    return APIResponse(success=True, message="Command completed").to_dict()


@app.get(f"/api/{API_VERSION}/agents/{{agent_id}}/paths")
async def get_agent_paths(agent_id: str, key_info: Dict = Depends(verify_api_key)):
    """Get available paths from an agent (from last list_paths command)"""
    paths = db_manager.get_agent_paths(agent_id)
    return APIResponse(success=True, message="OK", data=paths).to_dict()


# ==================== Enhanced API Key Management ====================

class APIKeyUpdate(BaseModel):
    """Request model for updating API key"""
    name: Optional[str] = None
    description: Optional[str] = None
    expires_at: Optional[str] = None  # ISO format datetime
    is_active: Optional[bool] = None


@app.put(f"/api/{API_VERSION}/keys/{{key_id}}")
async def update_api_key(key_id: str, request: APIKeyUpdate, key_info: Dict = Depends(verify_api_key)):
    """Update API key properties (name, description, expiration, active status)"""
    update_data = request.dict(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No update data provided")
    
    success = db_manager.update_api_key(key_id, update_data)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return APIResponse(success=True, message="API key updated").to_dict()


@app.get(f"/api/{API_VERSION}/keys/{{key_id}}/usage")
async def get_api_key_usage(key_id: str, days: int = 30, key_info: Dict = Depends(verify_api_key)):
    """Get API key usage statistics"""
    usage = db_manager.get_api_key_usage(key_id, days)
    return APIResponse(success=True, message="OK", data=usage).to_dict()


# ==================== Bootstrap API Key ====================

@app.post(f"/api/{API_VERSION}/bootstrap")
async def bootstrap_api_key(secret: str = Header(None, alias="X-Bootstrap-Secret")):
    """Create initial API key (only works if no keys exist)"""
    bootstrap_enabled = os.getenv("BOOTSTRAP_ENABLED", "true").lower() == "true"
    expected_secret = os.getenv("BOOTSTRAP_TOKEN", "")
    
    if not bootstrap_enabled:
        raise HTTPException(status_code=403, detail="Bootstrap is disabled")
    
    # If BOOTSTRAP_TOKEN is set, require it; otherwise allow without secret
    if expected_secret and secret != expected_secret:
        raise HTTPException(status_code=401, detail="Invalid bootstrap secret")
    
    # Check if any keys exist
    existing_keys = db_manager.list_api_keys()
    if existing_keys:
        raise HTTPException(status_code=400, detail="API keys already exist. Use existing key to create more.")
    
    key, key_id = db_manager.create_api_key("Bootstrap Key", "Initial API key created during setup")
    logger.warning("Bootstrap API key created - store this securely!")
    
    return APIResponse(
        success=True,
        message="Bootstrap API key created - SAVE THIS KEY!",
        data={"api_key": key, "key_id": key_id}
    ).to_dict()


# ==================== Main ====================

def main():
    """Run the API server"""
    config = ManagerConfig.from_env()
    
    ssl_config = {}
    if config.ssl_cert and config.ssl_key:
        ssl_config = {
            "ssl_keyfile": config.ssl_key,
            "ssl_certfile": config.ssl_cert
        }
    
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level=config.log_level.lower(),
        **ssl_config
    )


if __name__ == "__main__":
    main()
