"""
Continuous Monitoring Service for SecretSnipe

Watches for file changes and automatically runs multi-scanner analysis
with PostgreSQL/Redis backend. Includes scheduled reporting.
"""

import time
import logging
import json
import os
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import schedule
import requests

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from database_manager import (
    db_manager, project_manager, scan_session_manager,
    findings_manager, file_cache_manager, init_database
)
from redis_manager import redis_manager, scan_cache
import redis_manager as redis_module
from run_secret_scanner_pg import MultiScannerOrchestrator
from config import config

logger = logging.getLogger(__name__)

class FileChangeHandler(FileSystemEventHandler):
    """Handles file system events for continuous monitoring"""

    def __init__(self, monitor):
        self.monitor = monitor
        self.last_modified = {}
        self.event_cooldown = {}  # Track cooldown periods for files
        self.cooldown_seconds = 5.0  # Minimum seconds between processing the same file (increased from 2.0)
        self.processed_events = set()  # Track recently processed events

    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        # Skip excluded files and directories
        if self._is_excluded(file_path):
            return

        # Create a unique event identifier
        current_time = time.time()
        event_key = f"{file_path}:{int(current_time)}"

        # Check if we've already processed this event recently
        if event_key in self.processed_events:
            return

        # Check cooldown to prevent rapid successive events
        if file_path in self.event_cooldown:
            time_since_last = current_time - self.event_cooldown[file_path]
            if time_since_last < self.cooldown_seconds:
                return  # Still in cooldown period

        # Check if file actually changed (avoid duplicate events)
        try:
            current_mtime = file_path.stat().st_mtime
            # Allow for small timestamp differences (2 second tolerance)
            if file_path in self.last_modified:
                time_diff = abs(current_mtime - self.last_modified[file_path])
                if time_diff < 2.0:  # Less than 2 second difference
                    return
            self.last_modified[file_path] = current_mtime
        except OSError:
            return

        # Mark this event as processed
        self.processed_events.add(event_key)

        # Update cooldown timestamp
        self.event_cooldown[file_path] = current_time

        # Clean up old entries
        self._cleanup_old_entries()

        logger.info(f"File changed: {file_path}")
        self.monitor.queue_file_scan(file_path)

    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            file_path = Path(event.src_path)
            if not self._is_excluded(file_path):
                # Create a unique event identifier
                current_time = time.time()
                event_key = f"{file_path}:{int(current_time)}"

                # Check if we've already processed this event recently
                if event_key in self.processed_events:
                    return

                # Mark this event as processed
                self.processed_events.add(event_key)

                # Set cooldown for new files
                self.event_cooldown[file_path] = current_time
                logger.info(f"File created: {file_path}")
                self.monitor.queue_file_scan(file_path)

    def _cleanup_old_entries(self):
        """Clean up old entries from cooldown and last_modified dictionaries"""
        current_time = time.time()
        cutoff_time = current_time - 300  # 5 minutes ago

        # Clean up cooldown entries
        self.event_cooldown = {
            path: timestamp for path, timestamp in self.event_cooldown.items()
            if timestamp > cutoff_time
        }

        # Clean up processed events (keep only recent ones)
        current_minute = int(current_time // 60)
        self.processed_events = {
            event for event in self.processed_events
            if int(event.split(':')[1]) // 60 >= current_minute - 5  # Keep last 5 minutes
        }

        # Clean up last_modified entries (keep last 1000 entries to prevent memory issues)
        if len(self.last_modified) > 1000:
            # Sort by modification time and keep most recent 500
            sorted_entries = sorted(self.last_modified.items(), key=lambda x: x[1], reverse=True)
            self.last_modified = dict(sorted_entries[:500])

    def on_deleted(self, event):
        """Handle file deletion events"""
        if not event.is_directory:
            file_path = Path(event.src_path)
            logger.info(f"File deleted: {file_path}")
            # Note: We don't scan deleted files, but could log this event

    def _is_excluded(self, file_path: Path) -> bool:
        """Check if file should be excluded from monitoring"""
        # Check excluded directories
        for part in file_path.parts:
            if part in config.scanner.excluded_paths:
                return True

        # Check file extensions
        if file_path.suffix.lower() not in config.scanner.supported_extensions:
            return True

        return False

class ContinuousMonitor:
    """Continuous monitoring service for file changes"""

    def __init__(self, watch_directory: Path, project_name: str = "continuous-monitor"):
        self.watch_directory = watch_directory
        self.project_name = project_name
        self.observer = None
        self.event_handler = None
        self.running = False

        # File scan queue
        self.scan_queue = set()
        self.queue_lock = threading.Lock()

        # Initialize components
        self.orchestrator = MultiScannerOrchestrator()
        self.project_id = None
        self.session_id = None

        # Reporting
        self.last_report_time = datetime.now()

    def start(self):
        """Start the continuous monitoring service"""
        logger.info(f"Starting continuous monitoring for {self.watch_directory}")

        # Check if watch directory exists
        if not self.watch_directory.exists():
            logger.warning(f"Watch directory {self.watch_directory} does not exist, creating it")
            try:
                # Try to create in /tmp if /monitor fails
                if str(self.watch_directory) == "/monitor":
                    alt_dir = Path("/tmp/monitor")
                    logger.info(f"Trying alternative directory: {alt_dir}")
                    alt_dir.mkdir(parents=True, exist_ok=True)
                    self.watch_directory = alt_dir
                    logger.info(f"Using alternative watch directory {self.watch_directory}")
                else:
                    self.watch_directory.mkdir(parents=True, exist_ok=True)
                    logger.info(f"Created watch directory {self.watch_directory}")
            except Exception as e:
                logger.error(f"Failed to create watch directory {self.watch_directory}: {e}")
                return False

        # Initialize database and project
        if not self._initialize_project():
            logger.error("Failed to initialize monitoring project")
            return False

        # Start file system monitoring
        self.event_handler = FileChangeHandler(self)
        self.observer = Observer()
        self.observer.schedule(self.event_handler, str(self.watch_directory), recursive=False)
        self.observer.start()

        # Schedule weekly reports
        schedule.every().monday.at("09:00").do(self._generate_weekly_report)

        self.running = True
        logger.info("Continuous monitoring started successfully")

        # Main monitoring loop
        try:
            while self.running:
                # Process queued file scans
                self._process_scan_queue()

                # Run scheduled tasks
                schedule.run_pending()

                time.sleep(1)  # Check every second

        except KeyboardInterrupt:
            logger.info("Continuous monitoring stopping...")
            self.stop()

        return True

    def stop(self):
        """Stop the continuous monitoring service"""
        self.running = False

        if self.observer:
            self.observer.stop()
            self.observer.join()

        logger.info("Continuous monitoring stopped")

    def queue_file_scan(self, file_path: Path):
        """Queue a file for scanning"""
        with self.queue_lock:
            self.scan_queue.add(file_path)

    def _process_scan_queue(self):
        """Process queued files for scanning"""
        if not self.scan_queue:
            return

        with self.queue_lock:
            files_to_scan = list(self.scan_queue)
            self.scan_queue.clear()

        if files_to_scan:
            logger.info(f"Processing {len(files_to_scan)} changed files")
            self._scan_changed_files(files_to_scan)

    def _scan_changed_files(self, file_paths: List[Path]):
        """Scan changed files using all configured scanners"""
        try:
            # Create a temporary directory with just the changed files
            temp_dir = Path("/tmp/continuous_scan")
            temp_dir.mkdir(exist_ok=True)

            # Copy changed files to temp directory
            for file_path in file_paths:
                if file_path.exists():
                    relative_path = file_path.relative_to(self.watch_directory)
                    temp_file = temp_dir / relative_path
                    temp_file.parent.mkdir(parents=True, exist_ok=True)

                    try:
                        # Copy file content
                        with open(file_path, 'rb') as src, open(temp_file, 'wb') as dst:
                            dst.write(src.read())
                    except Exception as e:
                        logger.warning(f"Failed to copy {file_path}: {e}")
                        continue

            if any(temp_dir.rglob("*")):  # Check if any files were copied
                # Run multi-scanner on temp directory
                result = self.orchestrator.run_multi_scan(
                    directory=temp_dir,
                    project_name=f"{self.project_name}-changes",
                    scanners=['custom', 'trufflehog', 'gitleaks']
                )

                if result['success']:
                    logger.info(f"Scanned {len(file_paths)} changed files, found {result['total_findings']} findings")

                    # Check for critical findings and send notifications
                    self._check_critical_findings(result['session_id'])
                else:
                    logger.error(f"Failed to scan changed files: {result.get('error')}")

            # Clean up temp directory
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

        except Exception as e:
            logger.error(f"Error scanning changed files: {e}")

    def _check_critical_findings(self, session_id: str):
        """Check for critical findings and queue notifications"""
        try:
            query = """
                SELECT f.* FROM findings f
                WHERE f.scan_session_id = %s
                AND f.severity IN ('Critical', 'High')
                AND f.resolution_status = 'open'
            """
            critical_findings = db_manager.execute_query(query, (session_id,))

            for finding in critical_findings:
                # Queue webhook notification
                redis_module.notification_queue.queue_notification('default', finding)
                logger.info(f"Queued notification for critical finding: {finding['id']}")

        except Exception as e:
            logger.error(f"Error checking critical findings: {e}")

    def _initialize_project(self) -> bool:
        """Initialize monitoring project and session"""
        try:
            # Create or get project
            project = project_manager.get_project_by_name(self.project_name)
            if not project:
                self.project_id = project_manager.create_project(
                    name=self.project_name,
                    local_path=str(self.watch_directory),
                    description=f"Continuous monitoring of {self.watch_directory}"
                )
            else:
                self.project_id = project['id']

            if not self.project_id:
                return False

            # Create ongoing scan session
            self.session_id = scan_session_manager.create_session(
                project_id=self.project_id,
                scan_type='continuous',
                scan_parameters={
                    'watch_directory': str(self.watch_directory),
                    'monitoring_mode': True
                }
            )

            return self.session_id is not None

        except Exception as e:
            logger.error(f"Failed to initialize monitoring project: {e}")
            return False

    def _generate_weekly_report(self):
        """Generate and send weekly report"""
        try:
            logger.info("Generating weekly report...")

            # Get date range for last week
            week_end = datetime.now()
            week_start = week_end - timedelta(days=7)

            # Query findings from last week
            query = """
                SELECT
                    COUNT(*) as total_findings,
                    COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical_count,
                    COUNT(CASE WHEN severity = 'High' THEN 1 END) as high_count,
                    COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium_count,
                    COUNT(CASE WHEN tool_source = 'custom' THEN 1 END) as custom_findings,
                    COUNT(CASE WHEN tool_source = 'trufflehog' THEN 1 END) as trufflehog_findings,
                    COUNT(CASE WHEN tool_source = 'gitleaks' THEN 1 END) as gitleaks_findings
                FROM findings f
                JOIN scan_sessions ss ON f.scan_session_id = ss.id
                WHERE ss.project_id = %s
                AND f.first_seen >= %s
                AND f.first_seen <= %s
            """

            result = db_manager.execute_query(query, (self.project_id, week_start, week_end))

            if result:
                stats = result[0]
                self._send_teams_report(stats, week_start, week_end)

            self.last_report_time = datetime.now()

        except Exception as e:
            logger.error(f"Error generating weekly report: {e}")

    def _send_teams_report(self, stats: Dict[str, Any], week_start: datetime, week_end: datetime):
        """Send weekly report to Teams webhook"""
        try:
            # Prepare Teams card payload
            card_payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "0076D7",
                "summary": "Weekly SecretSnipe Security Report",
                "sections": [{
                    "activityTitle": "🔒 Weekly SecretSnipe Security Report",
                    "activitySubtitle": f"Monitoring: {self.watch_directory}",
                    "activityImage": "https://img.shields.io/badge/SecretSnipe-Security-blue",
                    "facts": [
                        {
                            "name": "Report Period",
                            "value": f"{week_start.strftime('%Y-%m-%d')} to {week_end.strftime('%Y-%m-%d')}"
                        },
                        {
                            "name": "Total Findings",
                            "value": str(stats['total_findings'])
                        },
                        {
                            "name": "Critical Issues",
                            "value": f"**{stats['critical_count']}**"
                        },
                        {
                            "name": "High Severity",
                            "value": str(stats['high_count'])
                        },
                        {
                            "name": "Medium Severity",
                            "value": str(stats['medium_count'])
                        }
                    ],
                    "text": f"**Scanner Breakdown:**\n\n"
                           f"• Custom Scanner: {stats['custom_findings']} findings\n"
                           f"• Trufflehog: {stats['trufflehog_findings']} findings\n"
                           f"• Gitleaks: {stats['gitleaks_findings']} findings"
                }],
                "potentialAction": [{
                    "@type": "OpenUri",
                    "name": "View Dashboard",
                    "targets": [{
                        "os": "default",
                        "uri": "http://localhost:8050"
                    }]
                }]
            }

            # Get webhook URL from config
            webhook_url = os.getenv('TEAMS_WEBHOOK_URL')
            if not webhook_url:
                logger.warning("TEAMS_WEBHOOK_URL not configured, skipping Teams notification")
                return

            # Send to Teams
            response = requests.post(
                webhook_url,
                json=card_payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )

            if response.status_code == 200:
                logger.info("Weekly report sent to Teams successfully")
            else:
                logger.error(f"Failed to send Teams report: {response.status_code} - {response.text}")

        except Exception as e:
            logger.error(f"Error sending Teams report: {e}")

def main():
    """Main entry point for continuous monitoring"""
    import argparse

    parser = argparse.ArgumentParser(description="Continuous Monitoring Service")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("--project", default="continuous-monitor", help="Project name")
    parser.add_argument("--teams-webhook", help="Teams webhook URL for reports")

    args = parser.parse_args()

    # Set Teams webhook URL if provided
    if args.teams_webhook:
        os.environ['TEAMS_WEBHOOK_URL'] = args.teams_webhook

    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Initialize database
    if not init_database():
        logger.error("Failed to initialize database")
        return 1

    # Initialize Redis
    if not redis_manager or not redis_manager.ping():
        logger.warning("Redis not available - continuing without caching")

    # Start continuous monitoring
    monitor = ContinuousMonitor(
        watch_directory=Path(args.directory),
        project_name=args.project
    )

    try:
        success = monitor.start()
        return 0 if success else 1
    except KeyboardInterrupt:
        monitor.stop()
        return 0

if __name__ == "__main__":
    exit(main())