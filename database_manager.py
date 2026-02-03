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

        # Extract file extension for optimized queries
        file_extension = self._extract_file_extension(file_path)

        # Extract file metadata from metadata dict if present
        file_modified_at = None
        file_size = None
        if metadata:
            file_modified_at_str = metadata.pop('file_modified_at', None)
            if file_modified_at_str and file_modified_at_str != 'None':
                try:
                    file_modified_at = datetime.fromisoformat(file_modified_at_str.replace(' ', 'T'))
                except Exception:
                    pass
            file_size = metadata.pop('file_size', None)

        # Check for existing finding
        existing = self._find_existing_finding(fingerprint)
        if existing:
            # Update last_seen for existing finding
            query = "UPDATE findings SET last_seen = NOW() WHERE id = %s RETURNING id"
            result = self.db.execute_query(query, (existing['id'],))
            return str(result[0]['id']) if result else None

        # Insert new finding with file metadata and extension
        query = """
            INSERT INTO findings (
                scan_session_id, project_id, file_path, line_number,
                secret_type, secret_value, context, severity,
                confidence_score, tool_source, fingerprint, metadata,
                file_modified_at, file_size, file_extension
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """

        params = (
            scan_session_id, project_id, file_path, line_number,
            secret_type, secret_value, context, severity,
            confidence_score, tool_source, fingerprint,
            json.dumps(metadata or {}),
            file_modified_at, file_size, file_extension
        )

        result = self.db.execute_query(query, params)
        return str(result[0]['id']) if result else None

    def _extract_file_extension(self, file_path: str) -> str:
        """Extract lowercase file extension from path for optimized chart queries"""
        import os
        if not file_path:
            return 'unknown'
        _, ext = os.path.splitext(file_path)
        if ext and ext.startswith('.'):
            return ext[1:].lower()[:20]  # Remove dot, lowercase, limit length
        return 'unknown'

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

    def mark_as_false_positive(self, finding_ids: List[str], reason: str = None, 
                               marked_by: str = "user") -> Dict[str, Any]:
        """Mark one or more findings as false positive
        
        Args:
            finding_ids: List of finding IDs to mark
            reason: Reason for marking as false positive
            marked_by: User or system marking the finding
            
        Returns:
            Dict with success count, failed count, and affected file paths
        """
        if not finding_ids:
            return {'success': 0, 'failed': 0, 'affected_files': []}
        
        results = {'success': 0, 'failed': 0, 'affected_files': set()}
        
        query = """
            UPDATE findings 
            SET resolution_status = 'false_positive',
                fp_reason = %s,
                fp_marked_by = %s,
                fp_marked_at = NOW(),
                resolved_at = NOW(),
                updated_at = NOW()
            WHERE id = %s
            RETURNING file_path
        """
        
        for finding_id in finding_ids:
            try:
                result = self.db.execute_query(query, (reason, marked_by, finding_id))
                if result:
                    results['success'] += 1
                    results['affected_files'].add(result[0]['file_path'])
                else:
                    results['failed'] += 1
            except Exception as e:
                logger.error(f"Error marking finding {finding_id} as FP: {e}")
                results['failed'] += 1
        
        results['affected_files'] = list(results['affected_files'])
        logger.info(f"Marked {results['success']} findings as false positive")
        return results

    def restore_from_false_positive(self, finding_ids: List[str]) -> Dict[str, Any]:
        """Restore findings from false positive back to open
        
        Args:
            finding_ids: List of finding IDs to restore
            
        Returns:
            Dict with success and failed counts
        """
        if not finding_ids:
            return {'success': 0, 'failed': 0}
        
        results = {'success': 0, 'failed': 0}
        
        query = """
            UPDATE findings 
            SET resolution_status = 'open',
                fp_reason = NULL,
                fp_marked_by = NULL,
                fp_marked_at = NULL,
                resolved_at = NULL,
                updated_at = NOW()
            WHERE id = %s AND resolution_status = 'false_positive'
        """
        
        for finding_id in finding_ids:
            try:
                affected = self.db.execute_update(query, (finding_id,))
                if affected > 0:
                    results['success'] += 1
                else:
                    results['failed'] += 1
            except Exception as e:
                logger.error(f"Error restoring finding {finding_id}: {e}")
                results['failed'] += 1
        
        logger.info(f"Restored {results['success']} findings from false positive")
        return results

    def get_false_positive_count(self) -> int:
        """Get count of false positive findings"""
        query = "SELECT COUNT(*) as count FROM findings WHERE resolution_status = 'false_positive'"
        result = self.db.execute_query(query, ())
        return result[0]['count'] if result else 0

    def get_false_positives(self, limit: int = 500) -> List[Dict[str, Any]]:
        """Get all false positive findings for review"""
        query = """
            SELECT id, file_path, secret_type, secret_value, severity, tool_source,
                   fp_reason, fp_marked_by, fp_marked_at, first_seen, file_modified_at
            FROM findings 
            WHERE resolution_status = 'false_positive'
            ORDER BY fp_marked_at DESC
            LIMIT %s
        """
        return self.db.execute_query(query, (limit,))

    def check_file_changes_for_fps(self) -> List[Dict[str, Any]]:
        """Check if files with false positive findings have been modified
        
        Returns files that have changed since the false positive was marked,
        indicating they should be rescanned.
        """
        query = """
            SELECT DISTINCT f.file_path, f.fp_marked_at, f.file_modified_at,
                   COUNT(*) as fp_count
            FROM findings f
            WHERE f.resolution_status = 'false_positive'
              AND f.file_modified_at IS NOT NULL
              AND f.fp_marked_at IS NOT NULL
            GROUP BY f.file_path, f.fp_marked_at, f.file_modified_at
        """
        return self.db.execute_query(query, ())

    def reset_fps_for_changed_files(self, file_paths: List[str]) -> int:
        """Reset false positives for files that have been modified
        
        When a file is modified, its previous false positive markings become
        invalid and should be re-evaluated.
        """
        if not file_paths:
            return 0
        
        placeholders = ','.join(['%s'] * len(file_paths))
        query = f"""
            UPDATE findings 
            SET resolution_status = 'open',
                fp_reason = CONCAT('Auto-reset: file modified since FP marked at ', fp_marked_at::text),
                updated_at = NOW()
            WHERE file_path IN ({placeholders})
              AND resolution_status = 'false_positive'
        """
        return self.db.execute_update(query, tuple(file_paths))

    def update_file_metadata(self, finding_id: str, file_modified_at: datetime, 
                           file_size: int) -> bool:
        """Update file metadata for a finding (used for change detection)"""
        query = """
            UPDATE findings 
            SET file_modified_at = %s, file_size = %s, updated_at = NOW()
            WHERE id = %s
        """
        return self.db.execute_update(query, (file_modified_at, file_size, finding_id)) > 0

    def cleanup_old_findings(self, days_old: int = 30) -> Dict[str, int]:
        """Clean up old findings and related data"""
        cutoff_date = datetime.now() - timedelta(days=days_old)

        results = {
            'scan_sessions_deleted': 0,
            'findings_deleted': 0,
            'cache_entries_deleted': 0
        }

        try:
            # Delete old scan sessions (completed/failed only)
            query = """
                DELETE FROM scan_sessions
                WHERE created_at < %s
                AND status IN ('completed', 'failed')
            """
            results['scan_sessions_deleted'] = self.db.execute_update(query, (cutoff_date,))

            # Delete orphaned findings (no associated scan session)
            query = """
                DELETE FROM findings
                WHERE scan_session_id NOT IN (
                    SELECT id FROM scan_sessions
                )
            """
            results['findings_deleted'] = self.db.execute_update(query, ())

            # Clean up old file cache entries
            query = """
                DELETE FROM file_cache
                WHERE processed_at < %s
            """
            results['cache_entries_deleted'] = self.db.execute_update(query, (cutoff_date,))

            logger.info(f"Cleanup completed: {results}")
            return results

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            raise

    def get_cleanup_stats(self) -> Dict[str, Any]:
        """Get statistics about data that could be cleaned up"""
        try:
            # Count old scan sessions
            old_sessions_query = """
                SELECT COUNT(*) as count
                FROM scan_sessions
                WHERE created_at < %s
                AND status IN ('completed', 'failed')
            """
            cutoff_date = datetime.now() - timedelta(days=30)
            old_sessions = self.db.execute_query(old_sessions_query, (cutoff_date,))

            # Count total findings
            total_findings_query = "SELECT COUNT(*) as count FROM findings"
            total_findings = self.db.execute_query(total_findings_query, ())

            # Count open findings
            open_findings_query = "SELECT COUNT(*) as count FROM findings WHERE resolution_status = 'open'"
            open_findings = self.db.execute_query(open_findings_query, ())

            # Database size estimate
            db_size_query = """
                SELECT
                    pg_size_pretty(pg_database_size(current_database())) as db_size,
                    pg_size_pretty(pg_total_relation_size('findings')) as findings_size,
                    pg_size_pretty(pg_total_relation_size('scan_sessions')) as sessions_size
            """
            sizes = self.db.execute_query(db_size_query, ())

            return {
                'old_sessions_count': old_sessions[0]['count'] if old_sessions else 0,
                'total_findings_count': total_findings[0]['count'] if total_findings else 0,
                'open_findings_count': open_findings[0]['count'] if open_findings else 0,
                'database_size': sizes[0] if sizes else {},
                'cutoff_date': cutoff_date.isoformat()
            }

        except Exception as e:
            logger.error(f"Error getting cleanup stats: {e}")
            return {}

    # =========================================================================
    # ENHANCED FINDINGS MANAGEMENT V2
    # =========================================================================

    def update_finding_category(self, finding_id: str, category: str, 
                                 updated_by: str = "user") -> bool:
        """Update the category of a finding
        
        Categories: real_password, real_api_key, finance_data, placeholder, 
                   test_data, sample_key, etc.
        """
        query = """
            UPDATE findings 
            SET finding_category = %s, updated_at = NOW()
            WHERE id = %s
        """
        affected = self.db.execute_update(query, (category, finding_id))
        
        if affected > 0:
            # Log to history
            self._log_finding_change(finding_id, 'finding_category', None, category, updated_by)
        
        return affected > 0

    def update_finding_severity(self, finding_id: str, new_severity: str,
                                 reason: str = None, adjusted_by: str = "user") -> bool:
        """Update severity with audit trail - preserves original severity
        
        Args:
            finding_id: The finding to update
            new_severity: New severity value (Critical, High, Medium, Low)
            reason: Reason for the adjustment
            adjusted_by: Who made the change
        """
        # Get current severity first
        current_query = "SELECT severity, original_severity FROM findings WHERE id = %s"
        current = self.db.execute_query(current_query, (finding_id,))
        
        if not current:
            return False
        
        old_severity = current[0]['severity']
        original = current[0].get('original_severity') or old_severity
        
        query = """
            UPDATE findings 
            SET severity = %s,
                original_severity = %s,
                severity_adjusted_by = %s,
                severity_adjusted_at = NOW(),
                severity_adjustment_reason = %s,
                updated_at = NOW()
            WHERE id = %s
        """
        affected = self.db.execute_update(query, (
            new_severity, original, adjusted_by, reason, finding_id
        ))
        
        if affected > 0:
            self._log_finding_change(finding_id, 'severity', old_severity, new_severity, adjusted_by)
        
        return affected > 0

    def update_finding_proof_content(self, finding_id: str, proof_content: str,
                                      start_line: int = None, end_line: int = None) -> bool:
        """Store full proof context for a finding"""
        query = """
            UPDATE findings 
            SET proof_content = %s,
                proof_start_line = %s,
                proof_end_line = %s,
                updated_at = NOW()
            WHERE id = %s
        """
        return self.db.execute_update(query, (
            proof_content, start_line, end_line, finding_id
        )) > 0

    def assign_owner(self, finding_id: str, owner_name: str, owner_email: str,
                     assigned_by: str = "user") -> bool:
        """Assign an owner to a finding for notification purposes"""
        query = """
            UPDATE findings 
            SET assigned_owner = %s,
                owner_email = %s,
                updated_at = NOW()
            WHERE id = %s
        """
        affected = self.db.execute_update(query, (owner_name, owner_email, finding_id))
        
        if affected > 0:
            self._log_finding_change(finding_id, 'assigned_owner', None, owner_email, assigned_by)
        
        return affected > 0

    def mark_file_as_clean(self, file_path: str, reason: str = None,
                           fp_category: str = None, marked_by: str = "user") -> Dict[str, Any]:
        """Mark all findings in a file as false positive
        
        This ensures symmetry between Group by File and All Findings views.
        """
        query = """
            UPDATE findings 
            SET resolution_status = 'false_positive',
                fp_reason = %s,
                fp_category = %s,
                fp_marked_by = %s,
                fp_marked_at = NOW(),
                resolved_at = NOW(),
                updated_at = NOW()
            WHERE file_path = %s AND resolution_status = 'open'
            RETURNING id
        """
        results = self.db.execute_query(query, (reason, fp_category, marked_by, file_path))
        
        affected_ids = [str(r['id']) for r in results] if results else []
        
        logger.info(f"Marked {len(affected_ids)} findings in {file_path} as false positive")
        
        return {
            'file_path': file_path,
            'findings_marked': len(affected_ids),
            'finding_ids': affected_ids
        }

    def get_findings_by_folder(self, folder_path: str, include_subfolders: bool = True,
                               resolution_status: str = 'open') -> List[Dict[str, Any]]:
        """Get all findings in a folder for grouped assignment"""
        if include_subfolders:
            query = """
                SELECT f.*, p.name as project_name
                FROM findings f
                LEFT JOIN projects p ON f.project_id = p.id
                WHERE f.file_path LIKE %s
                  AND f.resolution_status = %s
                ORDER BY f.parent_folder, f.file_path, f.line_number
            """
            pattern = f"{folder_path}%"
        else:
            query = """
                SELECT f.*, p.name as project_name
                FROM findings f
                LEFT JOIN projects p ON f.project_id = p.id
                WHERE f.parent_folder = %s
                  AND f.resolution_status = %s
                ORDER BY f.file_path, f.line_number
            """
            pattern = folder_path
        
        return self.db.execute_query(query, (pattern, resolution_status))

    def get_folder_summary(self) -> List[Dict[str, Any]]:
        """Get summary of findings grouped by parent folder"""
        query = """
            SELECT 
                parent_folder,
                COUNT(*) as finding_count,
                COUNT(DISTINCT file_path) as file_count,
                MAX(severity) as max_severity,
                array_agg(DISTINCT tool_source) as tools,
                array_agg(DISTINCT secret_type) as secret_types
            FROM findings
            WHERE resolution_status = 'open'
              AND parent_folder IS NOT NULL
            GROUP BY parent_folder
            ORDER BY finding_count DESC
        """
        return self.db.execute_query(query, ())

    def get_finding_categories(self) -> List[Dict[str, Any]]:
        """Get all available finding categories"""
        query = """
            SELECT category_key, display_name, description, color_code, icon, severity_weight
            FROM finding_categories
            WHERE is_active = true
            ORDER BY sort_order
        """
        return self.db.execute_query(query, ())

    def get_fp_categories(self) -> List[Dict[str, Any]]:
        """Get all available false positive categories"""
        query = """
            SELECT category_key, display_name, description
            FROM fp_categories
            WHERE is_active = true
            ORDER BY display_name
        """
        return self.db.execute_query(query, ())

    def get_findings_pending_escalation(self) -> List[Dict[str, Any]]:
        """Get findings that are approaching or past escalation date"""
        query = """
            SELECT f.*, p.name as project_name
            FROM findings f
            LEFT JOIN projects p ON f.project_id = p.id
            WHERE f.resolution_status = 'open'
              AND f.escalation_status = 'pending'
              AND f.escalation_date IS NOT NULL
            ORDER BY f.escalation_date ASC
        """
        return self.db.execute_query(query, ())

    def get_finding_with_proof(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get a single finding with all details including proof content"""
        query = """
            SELECT f.*, 
                   p.name as project_name,
                   fc.display_name as category_display,
                   fc.color_code as category_color,
                   fc.icon as category_icon
            FROM findings f
            LEFT JOIN projects p ON f.project_id = p.id
            LEFT JOIN finding_categories fc ON f.finding_category = fc.category_key
            WHERE f.id = %s
        """
        result = self.db.execute_query(query, (finding_id,))
        return dict(result[0]) if result else None

    def bulk_update_category(self, finding_ids: List[str], category: str,
                              updated_by: str = "user") -> Dict[str, Any]:
        """Update category for multiple findings at once"""
        if not finding_ids:
            return {'success': 0, 'failed': 0}
        
        results = {'success': 0, 'failed': 0}
        
        for finding_id in finding_ids:
            if self.update_finding_category(finding_id, category, updated_by):
                results['success'] += 1
            else:
                results['failed'] += 1
        
        return results

    def bulk_assign_owner(self, finding_ids: List[str], owner_name: str,
                          owner_email: str, assigned_by: str = "user") -> Dict[str, Any]:
        """Assign owner to multiple findings at once"""
        if not finding_ids:
            return {'success': 0, 'failed': 0}
        
        placeholders = ','.join(['%s'] * len(finding_ids))
        query = f"""
            UPDATE findings 
            SET assigned_owner = %s,
                owner_email = %s,
                updated_at = NOW()
            WHERE id IN ({placeholders})
        """
        
        params = [owner_name, owner_email] + list(finding_ids)
        affected = self.db.execute_update(query, tuple(params))
        
        return {'success': affected, 'failed': len(finding_ids) - affected}

    def _log_finding_change(self, finding_id: str, field_name: str,
                            old_value: Any, new_value: Any, changed_by: str):
        """Log a change to finding_history table"""
        try:
            query = """
                INSERT INTO finding_history (finding_id, field_changed, old_value, new_value, changed_by)
                VALUES (%s, %s, %s, %s, %s)
            """
            self.db.execute_update(query, (
                finding_id, field_name, str(old_value) if old_value else None,
                str(new_value) if new_value else None, changed_by
            ))
        except Exception as e:
            logger.warning(f"Could not log finding change: {e}")

    def refresh_materialized_views(self) -> bool:
        """Refresh materialized views for performance"""
        try:
            self.db.execute_update("SELECT refresh_findings_summary()", ())
            logger.info("Materialized views refreshed")
            return True
        except Exception as e:
            logger.warning(f"Could not refresh materialized views: {e}")
            return False

    def get_dashboard_summary_fast(self) -> Dict[str, Any]:
        """Get dashboard summary using materialized view for performance"""
        try:
            # Try materialized view first
            query = """
                SELECT 
                    SUM(open_count) as total_open,
                    SUM(fp_count) as total_fps,
                    SUM(CASE WHEN resolution_status = 'open' AND severity = 'Critical' THEN finding_count ELSE 0 END) as critical_count,
                    SUM(CASE WHEN resolution_status = 'open' AND severity = 'High' THEN finding_count ELSE 0 END) as high_count,
                    SUM(pending_escalation) as pending_escalations
                FROM mv_findings_summary
            """
            result = self.db.execute_query(query, ())
            if result:
                return dict(result[0])
        except Exception:
            pass
        
        # Fallback to direct query
        query = """
            SELECT 
                COUNT(CASE WHEN resolution_status = 'open' THEN 1 END) as total_open,
                COUNT(CASE WHEN resolution_status = 'false_positive' THEN 1 END) as total_fps,
                COUNT(CASE WHEN resolution_status = 'open' AND severity = 'Critical' THEN 1 END) as critical_count,
                COUNT(CASE WHEN resolution_status = 'open' AND severity = 'High' THEN 1 END) as high_count,
                COUNT(CASE WHEN escalation_status = 'pending' THEN 1 END) as pending_escalations
            FROM findings
        """
        result = self.db.execute_query(query, ())
        return dict(result[0]) if result else {}


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

    # Check if tables exist, if not create them
    try:
        with db_manager.get_cursor() as cursor:
            # Check if core tables exist
            cursor.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name IN ('projects', 'scan_sessions', 'findings')
            """)
            existing_tables = [row['table_name'] for row in cursor.fetchall()]
            
            if len(existing_tables) < 3:
                logger.info("Core tables missing, attempting to create from schema file...")
                
                # Try to read and execute schema file
                import os
                schema_file = os.path.join(os.path.dirname(__file__), 'database_schema.sql')
                if os.path.exists(schema_file):
                    with open(schema_file, 'r', encoding='utf-8') as f:
                        schema_sql = f.read()
                    
                    # Execute schema creation
                    cursor.execute(schema_sql)
                    logger.info("Database schema created successfully")
                else:
                    logger.warning("Schema file not found, tables may need manual creation")
            else:
                logger.info("Database tables already exist")

    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        return False

    logger.info("Database connection successful")
    return True

def close_database():
    """Close database connections"""
    db_manager.close_all()