"""
PostgreSQL Database Manager for SecretSnipe

Handles database connections, queries, and data operations for the
PostgreSQL backend with connection pooling and error handling.
"""

import psycopg2
import psycopg2.pool
import psycopg2.extras
import logging
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager
from datetime import datetime, timedelta
import json

from config import config

logger = logging.getLogger(__name__)

class DatabaseManager:
    """PostgreSQL database connection and operations manager"""

    def __init__(self):
        self._pool = None
        self._init_pool()

    def _init_pool(self):
        """Initialize connection pool"""
        try:
            self._pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=config.database.connection_pool_size,
                host=config.database.host,
                port=config.database.port,
                database=config.database.database,
                user=config.database.username,
                password=config.database.password,
                connect_timeout=config.database.connection_timeout
            )
            logger.info("Database connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database connection pool: {e}")
            raise

    @contextmanager
    def get_connection(self):
        """Get database connection from pool"""
        conn = None
        try:
            conn = self._pool.getconn()
            yield conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                self._pool.putconn(conn)

    @contextmanager
    def get_cursor(self):
        """Get database cursor with automatic connection management"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                yield cursor
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Database operation error: {e}")
                raise
            finally:
                cursor.close()

    def execute_query(self, query: str, params: Tuple = None) -> List[Dict[str, Any]]:
        """Execute SELECT query and return results"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())
            return [dict(row) for row in cursor.fetchall()]

    def execute_update(self, query: str, params: Tuple = None) -> int:
        """Execute INSERT/UPDATE/DELETE query and return affected rows"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())
            return cursor.rowcount

    def health_check(self) -> bool:
        """Check database connectivity"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    def close_all(self):
        """Close all connections in pool"""
        if self._pool:
            self._pool.closeall()
            logger.info("Database connection pool closed")


class ProjectManager:
    """Project management operations"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def create_project(self, name: str, repository_url: Optional[str] = None,
                      local_path: Optional[str] = None, description: Optional[str] = None) -> str:
        """Create a new project"""
        query = """
            INSERT INTO projects (name, repository_url, local_path, description)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """
        result = self.db.execute_query(query, (name, repository_url, local_path, description))
        return str(result[0]['id']) if result else None

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Get project by ID"""
        query = "SELECT * FROM projects WHERE id = %s AND is_active = true"
        result = self.db.execute_query(query, (project_id,))
        return dict(result[0]) if result else None

    def update_project_scan_time(self, project_id: str):
        """Update project's last scan time"""
        query = "UPDATE projects SET last_scan_at = NOW() WHERE id = %s"
        self.db.execute_update(query, (project_id,))

    def get_project_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get project by name"""
        query = "SELECT * FROM projects WHERE name = %s AND is_active = true"
        result = self.db.execute_query(query, (name,))
        return dict(result[0]) if result else None


class ScanSessionManager:
    """Scan session management operations"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def create_session(self, project_id: str, scan_type: str,
                      scan_parameters: Optional[Dict[str, Any]] = None) -> str:
        """Create a new scan session"""
        query = """
            INSERT INTO scan_sessions (project_id, scan_type, scan_parameters)
            VALUES (%s, %s, %s)
            RETURNING id
        """
        params = json.dumps(scan_parameters or {})
        result = self.db.execute_query(query, (project_id, scan_type, params))
        return str(result[0]['id']) if result else None

    def update_session_status(self, session_id: str, status: str,
                             total_files: int = 0, total_findings: int = 0,
                             error_message: Optional[str] = None):
        """Update scan session status"""
        query = """
            UPDATE scan_sessions
            SET status = %s, completed_at = NOW(),
                total_files_scanned = %s, total_findings = %s,
                error_message = %s
            WHERE id = %s
        """
        self.db.execute_update(query, (status, total_files, total_findings, error_message, session_id))

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get scan session by ID"""
        query = "SELECT * FROM scan_sessions WHERE id = %s"
        result = self.db.execute_query(query, (session_id,))
        return dict(result[0]) if result else None


class FindingsManager:
    """Findings management operations"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def insert_finding(self, scan_session_id: str, project_id: str,
                      file_path: str, secret_type: str, secret_value: str,
                      context: str = "", severity: str = "Medium",
                      line_number: Optional[int] = None,
                      confidence_score: Optional[float] = None,
                      tool_source: str = "custom",
                      metadata: Optional[Dict[str, Any]] = None) -> str:
        """Insert a new finding"""

        # Generate fingerprint for deduplication
        fingerprint = self._generate_fingerprint(
            file_path, secret_type, secret_value, line_number
        )

        # Check for existing finding
        existing = self._find_existing_finding(fingerprint)
        if existing:
            # Update last_seen for existing finding
            query = "UPDATE findings SET last_seen = NOW() WHERE id = %s RETURNING id"
            result = self.db.execute_query(query, (existing['id'],))
            return str(result[0]['id']) if result else None

        # Insert new finding
        query = """
            INSERT INTO findings (
                scan_session_id, project_id, file_path, line_number,
                secret_type, secret_value, context, severity,
                confidence_score, tool_source, fingerprint, metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """

        params = (
            scan_session_id, project_id, file_path, line_number,
            secret_type, secret_value, context, severity,
            confidence_score, tool_source, fingerprint,
            json.dumps(metadata or {})
        )

        result = self.db.execute_query(query, params)
        return str(result[0]['id']) if result else None

    def _generate_fingerprint(self, file_path: str, secret_type: str,
                            secret_value: str, line_number: Optional[int]) -> str:
        """Generate fingerprint for finding deduplication"""
        import hashlib
        data = f"{file_path}|{secret_type}|{secret_value}|{line_number or ''}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _find_existing_finding(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Find existing finding by fingerprint"""
        query = "SELECT id FROM findings WHERE fingerprint = %s AND resolution_status = 'open'"
        result = self.db.execute_query(query, (fingerprint,))
        return dict(result[0]) if result else None

    def get_findings_by_session(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all findings for a scan session"""
        query = "SELECT * FROM findings WHERE scan_session_id = %s ORDER BY file_path, line_number"
        return self.db.execute_query(query, (session_id,))

    def get_findings_by_project(self, project_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get findings for a project"""
        query = """
            SELECT f.*, ss.scan_type, ss.started_at
            FROM findings f
            JOIN scan_sessions ss ON f.scan_session_id = ss.id
            WHERE f.project_id = %s AND f.resolution_status = 'open'
            ORDER BY f.first_seen DESC
            LIMIT %s
        """
        return self.db.execute_query(query, (project_id, limit))

    def update_finding_status(self, finding_id: str, status: str,
                            resolution_reason: Optional[str] = None):
        """Update finding resolution status"""
        if status == 'resolved':
            query = """
                UPDATE findings
                SET resolution_status = %s, resolved_at = NOW()
                WHERE id = %s
            """
            self.db.execute_update(query, (status, finding_id))
        else:
            query = "UPDATE findings SET resolution_status = %s WHERE id = %s"
            self.db.execute_update(query, (status, finding_id))


class FileCacheManager:
    """File processing cache operations"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def cache_file(self, file_path: str, file_hash: str, scan_session_id: str):
        """Cache processed file information"""
        query = """
            INSERT INTO file_cache (file_path, file_hash, scan_session_id, processed_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (file_path, file_hash)
            DO UPDATE SET processed_at = NOW(), scan_session_id = EXCLUDED.scan_session_id
        """
        self.db.execute_update(query, (file_path, file_hash, scan_session_id))

    def is_file_changed(self, file_path: str, current_hash: str) -> bool:
        """Check if file has changed since last processing"""
        query = "SELECT file_hash FROM file_cache WHERE file_path = %s ORDER BY processed_at DESC LIMIT 1"
        result = self.db.execute_query(query, (file_path,))
        if result:
            return result[0]['file_hash'] != current_hash
        return True  # File not in cache, consider it changed


# Global instances
db_manager = DatabaseManager()
project_manager = ProjectManager(db_manager)
scan_session_manager = ScanSessionManager(db_manager)
findings_manager = FindingsManager(db_manager)
file_cache_manager = FileCacheManager(db_manager)

def init_database():
    """Initialize database connection and create tables if needed"""
    if not db_manager.health_check():
        logger.error("Database connection failed")
        return False

    logger.info("Database connection successful")
    return True

def close_database():
    """Close database connections"""
    db_manager.close_all()