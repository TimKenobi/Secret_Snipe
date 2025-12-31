"""
Project and Directory Manager for SecretSnipe

Manages multiple scan directories and projects, enabling:
- Adding/removing scan directories
- Triggering custom scans on specific directories
- Managing scan schedules
- Project-based organization

Usage:
    from project_manager import project_manager
    
    # Add a new directory to scan
    project_manager.add_directory('/path/to/scan', 'My Project', 'Description')
    
    # Trigger a scan
    project_manager.request_scan(directory_id, scan_type='full')
    
    # Get all directories
    directories = project_manager.get_all_directories()
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path

from database_manager import DatabaseManager
from psycopg2.extras import Json

logger = logging.getLogger(__name__)


@dataclass
class ScanDirectory:
    """Represents a scan directory configuration"""
    id: str
    project_id: str
    directory_path: str
    display_name: str
    description: str = ""
    is_active: bool = True
    scan_priority: int = 5
    last_scan_at: Optional[datetime] = None
    last_scan_status: Optional[str] = None
    total_files: int = 0
    total_findings: int = 0
    scan_schedule: str = "daily"
    exclude_patterns: List[str] = field(default_factory=list)
    include_patterns: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class ScanRequest:
    """Represents a scan request"""
    id: str
    directory_id: str
    project_id: str
    scan_type: str
    status: str
    requested_by: str
    requested_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    files_scanned: int = 0
    findings_count: int = 0
    error_message: Optional[str] = None
    scan_options: Dict[str, Any] = field(default_factory=dict)


class ProjectManager:
    """Manages projects and scan directories"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()
        self._ensure_tables_exist()
    
    def _ensure_tables_exist(self):
        """Ensure the scan_directories and scan_requests tables exist"""
        try:
            # Check if tables exist
            check_query = """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'scan_directories'
                );
            """
            result = self.db.execute_query(check_query)
            if result and result[0].get('exists'):
                logger.info("Project management tables already exist")
                return True
            
            logger.info("Project management tables not found - they will be created when migration is run")
            return False
        except Exception as e:
            logger.warning(f"Could not check for project tables: {e}")
            return False
    
    # =========================================================================
    # Directory Management
    # =========================================================================
    
    def add_directory(self, directory_path: str, display_name: str, 
                      description: str = "", project_name: str = "Default Project",
                      scan_schedule: str = "daily", scan_priority: int = 5,
                      exclude_patterns: List[str] = None,
                      include_patterns: List[str] = None) -> Optional[str]:
        """
        Add a new directory for scanning.
        
        Args:
            directory_path: Absolute path to the directory
            display_name: User-friendly name for the directory
            description: Optional description
            project_name: Project to associate with (creates if doesn't exist)
            scan_schedule: 'hourly', 'daily', 'weekly', 'manual'
            scan_priority: 1-10 (1=highest priority)
            exclude_patterns: List of glob patterns to exclude
            include_patterns: List of glob patterns to include (if set, only these)
        
        Returns:
            Directory ID if successful, None otherwise
        """
        try:
            # Validate directory exists (if accessible)
            path = Path(directory_path)
            if not directory_path.startswith('/scan'):
                # Only validate paths outside /scan container mount
                if path.exists() and not path.is_dir():
                    raise ValueError(f"Path exists but is not a directory: {directory_path}")
            
            # Get or create project
            project_id = self._get_or_create_project(project_name)
            if not project_id:
                raise ValueError(f"Could not get/create project: {project_name}")
            
            # Insert directory
            query = """
                INSERT INTO scan_directories (
                    project_id, directory_path, display_name, description,
                    scan_schedule, scan_priority, exclude_patterns, include_patterns,
                    is_active
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, true)
                ON CONFLICT (directory_path) DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    description = EXCLUDED.description,
                    scan_schedule = EXCLUDED.scan_schedule,
                    scan_priority = EXCLUDED.scan_priority,
                    exclude_patterns = EXCLUDED.exclude_patterns,
                    include_patterns = EXCLUDED.include_patterns,
                    updated_at = NOW()
                RETURNING id;
            """
            result = self.db.execute_query(
                query,
                (project_id, directory_path, display_name, description,
                 scan_schedule, scan_priority, 
                 exclude_patterns or [], include_patterns or [])
            )
            
            if result:
                dir_id = str(result[0]['id'])
                logger.info(f"Added/updated scan directory: {display_name} ({directory_path}) -> {dir_id}")
                return dir_id
            return None
            
        except Exception as e:
            logger.error(f"Error adding directory {directory_path}: {e}")
            return None
    
    def remove_directory(self, directory_id: str, delete_findings: bool = False) -> bool:
        """
        Remove a scan directory.
        
        Args:
            directory_id: ID of the directory to remove
            delete_findings: If True, also delete all findings from this directory
        
        Returns:
            True if successful
        """
        try:
            if delete_findings:
                # Get the directory path first
                path_query = "SELECT directory_path FROM scan_directories WHERE id = %s"
                result = self.db.execute_query(path_query, (directory_id,))
                if result:
                    dir_path = result[0]['directory_path']
                    # Delete findings with this path prefix
                    delete_findings_query = """
                        DELETE FROM findings WHERE file_path LIKE %s
                    """
                    self.db.execute_query(delete_findings_query, (f"{dir_path}%",))
                    logger.info(f"Deleted findings for directory: {dir_path}")
            
            # Delete the directory record
            delete_query = "DELETE FROM scan_directories WHERE id = %s RETURNING id"
            result = self.db.execute_query(delete_query, (directory_id,))
            
            if result:
                logger.info(f"Removed scan directory: {directory_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error removing directory {directory_id}: {e}")
            return False
    
    def update_directory(self, directory_id: str, **kwargs) -> bool:
        """
        Update directory settings.
        
        Args:
            directory_id: ID of the directory
            **kwargs: Fields to update (display_name, description, is_active, 
                      scan_schedule, scan_priority, exclude_patterns, include_patterns)
        
        Returns:
            True if successful
        """
        allowed_fields = {
            'display_name', 'description', 'is_active', 'scan_schedule',
            'scan_priority', 'exclude_patterns', 'include_patterns', 'metadata'
        }
        
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        if not updates:
            return False
        
        try:
            set_clauses = [f"{k} = %s" for k in updates.keys()]
            set_clauses.append("updated_at = NOW()")
            
            query = f"""
                UPDATE scan_directories 
                SET {', '.join(set_clauses)}
                WHERE id = %s
                RETURNING id
            """
            
            params = list(updates.values()) + [directory_id]
            result = self.db.execute_query(query, tuple(params))
            
            return bool(result)
            
        except Exception as e:
            logger.error(f"Error updating directory {directory_id}: {e}")
            return False
    
    def get_directory(self, directory_id: str) -> Optional[ScanDirectory]:
        """Get a single directory by ID"""
        try:
            query = """
                SELECT * FROM scan_directories WHERE id = %s
            """
            result = self.db.execute_query(query, (directory_id,))
            if result:
                return self._row_to_directory(result[0])
            return None
        except Exception as e:
            logger.error(f"Error getting directory {directory_id}: {e}")
            return None
    
    def get_all_directories(self, active_only: bool = False) -> List[ScanDirectory]:
        """Get all scan directories"""
        try:
            query = """
                SELECT sd.*, p.name as project_name
                FROM scan_directories sd
                JOIN projects p ON sd.project_id = p.id
            """
            if active_only:
                query += " WHERE sd.is_active = true"
            query += " ORDER BY sd.scan_priority, sd.display_name"
            
            results = self.db.execute_query(query)
            return [self._row_to_directory(row) for row in results] if results else []
            
        except Exception as e:
            logger.error(f"Error getting directories: {e}")
            return []
    
    def get_directories_for_project(self, project_id: str) -> List[ScanDirectory]:
        """Get all directories for a specific project"""
        try:
            query = """
                SELECT * FROM scan_directories 
                WHERE project_id = %s
                ORDER BY scan_priority, display_name
            """
            results = self.db.execute_query(query, (project_id,))
            return [self._row_to_directory(row) for row in results] if results else []
            
        except Exception as e:
            logger.error(f"Error getting directories for project {project_id}: {e}")
            return []
    
    # =========================================================================
    # Scan Request Management
    # =========================================================================
    
    def request_scan(self, directory_id: str, scan_type: str = 'full',
                     requested_by: str = 'dashboard_user',
                     scan_options: Dict[str, Any] = None) -> Optional[str]:
        """
        Request a scan for a specific directory.
        
        Args:
            directory_id: ID of the directory to scan
            scan_type: 'full', 'incremental', 'custom_only', 'trufflehog_only', 'gitleaks_only'
            requested_by: Username of requester
            scan_options: Additional options (e.g., force_rescan, max_files)
        
        Returns:
            Scan request ID if successful
        """
        try:
            # Get directory info
            dir_info = self.get_directory(directory_id)
            if not dir_info:
                raise ValueError(f"Directory not found: {directory_id}")
            
            if not dir_info.is_active:
                raise ValueError(f"Directory is not active: {dir_info.display_name}")
            
            # Check for existing pending/running scan
            check_query = """
                SELECT id FROM scan_requests 
                WHERE directory_id = %s AND status IN ('pending', 'queued', 'running')
                LIMIT 1
            """
            existing = self.db.execute_query(check_query, (directory_id,))
            if existing:
                logger.warning(f"Scan already pending/running for directory {directory_id}")
                return str(existing[0]['id'])
            
            # Create scan request
            query = """
                INSERT INTO scan_requests (
                    directory_id, project_id, scan_type, status,
                    requested_by, scan_options
                ) VALUES (%s, %s, %s, 'pending', %s, %s)
                RETURNING id
            """
            result = self.db.execute_query(
                query,
                (directory_id, dir_info.project_id, scan_type, 
                 requested_by, Json(scan_options or {}))
            )
            
            if result:
                request_id = str(result[0]['id'])
                logger.info(f"Created scan request {request_id} for {dir_info.display_name} ({scan_type})")
                return request_id
            return None
            
        except Exception as e:
            logger.error(f"Error requesting scan for {directory_id}: {e}")
            return None
    
    def cancel_scan(self, request_id: str) -> bool:
        """Cancel a pending scan request"""
        try:
            query = """
                UPDATE scan_requests 
                SET status = 'cancelled', completed_at = NOW()
                WHERE id = %s AND status IN ('pending', 'queued')
                RETURNING id
            """
            result = self.db.execute_query(query, (request_id,))
            return bool(result)
        except Exception as e:
            logger.error(f"Error cancelling scan {request_id}: {e}")
            return False
    
    def get_pending_scans(self) -> List[ScanRequest]:
        """Get all pending scan requests ordered by priority"""
        try:
            query = """
                SELECT sr.*, sd.scan_priority, sd.directory_path, sd.display_name
                FROM scan_requests sr
                JOIN scan_directories sd ON sr.directory_id = sd.id
                WHERE sr.status IN ('pending', 'queued')
                ORDER BY sd.scan_priority, sr.requested_at
            """
            results = self.db.execute_query(query)
            return [self._row_to_request(row) for row in results] if results else []
        except Exception as e:
            logger.error(f"Error getting pending scans: {e}")
            return []
    
    def get_scan_history(self, directory_id: str = None, limit: int = 50) -> List[ScanRequest]:
        """Get scan history for a directory or all directories"""
        try:
            query = """
                SELECT sr.*, sd.display_name, sd.directory_path
                FROM scan_requests sr
                JOIN scan_directories sd ON sr.directory_id = sd.id
            """
            params = []
            if directory_id:
                query += " WHERE sr.directory_id = %s"
                params.append(directory_id)
            query += f" ORDER BY sr.requested_at DESC LIMIT {limit}"
            
            results = self.db.execute_query(query, tuple(params) if params else None)
            return [self._row_to_request(row) for row in results] if results else []
        except Exception as e:
            logger.error(f"Error getting scan history: {e}")
            return []
    
    def update_scan_status(self, request_id: str, status: str, 
                           files_scanned: int = None, findings_count: int = None,
                           error_message: str = None) -> bool:
        """Update the status of a scan request"""
        try:
            updates = ["status = %s"]
            params = [status]
            
            if status == 'running':
                updates.append("started_at = NOW()")
            elif status in ('completed', 'failed'):
                updates.append("completed_at = NOW()")
            
            if files_scanned is not None:
                updates.append("files_scanned = %s")
                params.append(files_scanned)
            if findings_count is not None:
                updates.append("findings_count = %s")
                params.append(findings_count)
            if error_message:
                updates.append("error_message = %s")
                params.append(error_message)
            
            params.append(request_id)
            
            query = f"""
                UPDATE scan_requests SET {', '.join(updates)}
                WHERE id = %s RETURNING id
            """
            result = self.db.execute_query(query, tuple(params))
            
            # Also update the directory's last scan info
            if status in ('completed', 'failed'):
                self._update_directory_scan_status(request_id, status, files_scanned, findings_count)
            
            return bool(result)
        except Exception as e:
            logger.error(f"Error updating scan status {request_id}: {e}")
            return False
    
    def _update_directory_scan_status(self, request_id: str, status: str,
                                       files_scanned: int, findings_count: int):
        """Update directory with latest scan results"""
        try:
            query = """
                UPDATE scan_directories sd
                SET 
                    last_scan_at = NOW(),
                    last_scan_status = %s,
                    total_files = COALESCE(%s, total_files),
                    total_findings = COALESCE(%s, total_findings),
                    updated_at = NOW()
                FROM scan_requests sr
                WHERE sr.id = %s AND sd.id = sr.directory_id
            """
            self.db.execute_query(query, (status, files_scanned, findings_count, request_id))
        except Exception as e:
            logger.warning(f"Could not update directory scan status: {e}")
    
    # =========================================================================
    # Project Management
    # =========================================================================
    
    def _get_or_create_project(self, project_name: str) -> Optional[str]:
        """Get existing project or create new one"""
        try:
            # Try to get existing
            query = "SELECT id FROM projects WHERE name = %s"
            result = self.db.execute_query(query, (project_name,))
            if result:
                return str(result[0]['id'])
            
            # Create new
            create_query = """
                INSERT INTO projects (name, is_active)
                VALUES (%s, true)
                RETURNING id
            """
            result = self.db.execute_query(create_query, (project_name,))
            if result:
                return str(result[0]['id'])
            return None
        except Exception as e:
            logger.error(f"Error getting/creating project {project_name}: {e}")
            return None
    
    def get_all_projects(self) -> List[Dict[str, Any]]:
        """Get all projects with their directory counts"""
        try:
            query = """
                SELECT 
                    p.*,
                    COUNT(sd.id) as directory_count,
                    SUM(CASE WHEN sd.is_active THEN 1 ELSE 0 END) as active_directories
                FROM projects p
                LEFT JOIN scan_directories sd ON p.id = sd.project_id
                GROUP BY p.id
                ORDER BY p.name
            """
            return self.db.execute_query(query) or []
        except Exception as e:
            logger.error(f"Error getting projects: {e}")
            return []
    
    def create_project(self, name: str, description: str = "") -> Optional[str]:
        """Create a new project"""
        try:
            query = """
                INSERT INTO projects (name, description, is_active)
                VALUES (%s, %s, true)
                ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
                RETURNING id
            """
            result = self.db.execute_query(query, (name, description))
            if result:
                return str(result[0]['id'])
            return None
        except Exception as e:
            logger.error(f"Error creating project {name}: {e}")
            return None
    
    # =========================================================================
    # Helpers
    # =========================================================================
    
    def _row_to_directory(self, row: Dict) -> ScanDirectory:
        """Convert database row to ScanDirectory"""
        return ScanDirectory(
            id=str(row['id']),
            project_id=str(row['project_id']),
            directory_path=row['directory_path'],
            display_name=row['display_name'],
            description=row.get('description', ''),
            is_active=row.get('is_active', True),
            scan_priority=row.get('scan_priority', 5),
            last_scan_at=row.get('last_scan_at'),
            last_scan_status=row.get('last_scan_status'),
            total_files=row.get('total_files', 0),
            total_findings=row.get('total_findings', 0),
            scan_schedule=row.get('scan_schedule', 'daily'),
            exclude_patterns=row.get('exclude_patterns', []),
            include_patterns=row.get('include_patterns', []),
            metadata=row.get('metadata', {})
        )
    
    def _row_to_request(self, row: Dict) -> ScanRequest:
        """Convert database row to ScanRequest"""
        return ScanRequest(
            id=str(row['id']),
            directory_id=str(row['directory_id']),
            project_id=str(row['project_id']),
            scan_type=row['scan_type'],
            status=row['status'],
            requested_by=row.get('requested_by', 'unknown'),
            requested_at=row['requested_at'],
            started_at=row.get('started_at'),
            completed_at=row.get('completed_at'),
            files_scanned=row.get('files_scanned', 0),
            findings_count=row.get('findings_count', 0),
            error_message=row.get('error_message'),
            scan_options=row.get('scan_options', {})
        )
    
    def get_directory_stats(self) -> Dict[str, Any]:
        """Get summary statistics for all directories"""
        try:
            query = """
                SELECT 
                    COUNT(*) as total_directories,
                    SUM(CASE WHEN is_active THEN 1 ELSE 0 END) as active_directories,
                    SUM(total_files) as total_files,
                    SUM(total_findings) as total_findings,
                    COUNT(DISTINCT project_id) as total_projects
                FROM scan_directories
            """
            result = self.db.execute_query(query)
            return dict(result[0]) if result else {}
        except Exception as e:
            logger.error(f"Error getting directory stats: {e}")
            return {}


# Global instance
project_manager = ProjectManager()
