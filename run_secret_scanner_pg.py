"""
Unified Multi-Scanner Orchestrator for SecretSnipe

Coordinates execution of custom scanner, Trufflehog, and Gitleaks
with unified PostgreSQL/Redis backend.
"""

import argparse
import logging
import subprocess
import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from database_manager import (
    db_manager, project_manager, scan_session_manager,
    findings_manager, file_cache_manager, init_database
)
from redis_manager import redis_manager, cache_manager, scan_cache, init_redis
from config import config

logger = logging.getLogger(__name__)

class MultiScannerOrchestrator:
    """Orchestrates multiple secret scanners"""

    def __init__(self):
        self.scanners = {
            'custom': self._run_custom_scanner,
            'trufflehog': self._run_trufflehog,
            'gitleaks': self._run_gitleaks
        }

    def _run_custom_scanner(self, directory: Path, project_id: str, session_id: str) -> Dict[str, Any]:
        """Run the custom SecretSnipe scanner"""
        try:
            from secret_snipe_pg import scan_directory, load_signatures

            # Load signatures before scanning
            if not load_signatures():
                return {'success': False, 'findings': 0, 'errors': ['Failed to load signatures']}

            findings_count = scan_directory(directory, f"project_{project_id}", max_workers=config.scanner.threads)
            if findings_count < 0:
                return {'success': False, 'findings': 0, 'errors': ['Scan failed']}
            return {'success': True, 'findings': findings_count, 'errors': []}
        except Exception as e:
            logger.error(f"Custom scanner error: {e}")
            return {'success': False, 'findings': 0, 'errors': [str(e)]}

    def _run_trufflehog(self, directory: Path, project_id: str, session_id: str) -> Dict[str, Any]:
        """Run Trufflehog scanner"""
        try:
            # Check if trufflehog is available
            result = subprocess.run(['trufflehog', '--version'],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return {'success': False, 'findings': 0, 'errors': ['Trufflehog not available']}

            # Run trufflehog scan
            cmd = [
                'trufflehog', 'filesystem',
                '--directory', str(directory),
                '--json',
                '--no-update'  # Disable updater to prevent permission issues
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                # Parse JSON output and store findings
                findings = self._parse_trufflehog_output(result.stdout, session_id, project_id)
                return {'success': True, 'findings': len(findings), 'errors': []}
            else:
                return {'success': False, 'findings': 0, 'errors': [result.stderr]}

        except subprocess.TimeoutExpired:
            return {'success': False, 'findings': 0, 'errors': ['Trufflehog scan timeout']}
        except Exception as e:
            logger.error(f"Trufflehog scanner error: {e}")
            return {'success': False, 'findings': 0, 'errors': [str(e)]}

    def _run_gitleaks(self, directory: Path, project_id: str, session_id: str) -> Dict[str, Any]:
        """Run Gitleaks scanner"""
        try:
            # Check if gitleaks is available
            result = subprocess.run(['gitleaks', 'version'],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return {'success': False, 'findings': 0, 'errors': ['Gitleaks not available']}

            # Create temporary file for results
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', suffix='_gitleaks.json', delete=False) as temp_file:
                temp_results_path = temp_file.name

            # Run gitleaks scan
            cmd = [
                'gitleaks', 'detect',
                '--source', str(directory),
                '--report-format', 'json',
                '--report-path', temp_results_path,
                '--no-git'  # Allow scanning non-git directories
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0 or result.returncode == 1:  # Gitleaks returns 1 when findings found
                # Parse results and store findings
                findings = self._parse_gitleaks_output(temp_results_path, session_id, project_id)
                return {'success': True, 'findings': len(findings), 'errors': []}
            else:
                # Clean up temp file on error
                if os.path.exists(temp_results_path):
                    os.remove(temp_results_path)
                return {'success': False, 'findings': 0, 'errors': [result.stderr]}

        except subprocess.TimeoutExpired:
            return {'success': False, 'findings': 0, 'errors': ['Gitleaks scan timeout']}
        except Exception as e:
            logger.error(f"Gitleaks scanner error: {e}")
            return {'success': False, 'findings': 0, 'errors': [str(e)]}

    def _parse_trufflehog_output(self, output: str, session_id: str, project_id: str) -> List[str]:
        """Parse Trufflehog JSON output and store findings"""
        findings_ids = []
        try:
            lines = output.strip().split('\n')
            for line in lines:
                if line.strip():
                    finding_data = json.loads(line)
                    finding_id = findings_manager.insert_finding(
                        scan_session_id=session_id,
                        project_id=project_id,
                        file_path=finding_data.get('path', ''),
                        secret_type=finding_data.get('detector_name', 'unknown'),
                        secret_value=finding_data.get('raw', ''),
                        context=finding_data.get('context', ''),
                        severity='High',  # Trufflehog typically finds high-severity issues
                        line_number=finding_data.get('line_number'),
                        tool_source='trufflehog',
                        metadata=finding_data
                    )
                    if finding_id:
                        findings_ids.append(finding_id)
        except Exception as e:
            logger.error(f"Error parsing Trufflehog output: {e}")
        return findings_ids

    def _parse_gitleaks_output(self, results_file: str, session_id: str, project_id: str) -> List[str]:
        """Parse Gitleaks JSON output and store findings"""
        findings_ids = []
        try:
            if os.path.exists(results_file):
                with open(results_file, 'r') as f:
                    results = json.load(f)

                for finding in results:
                    finding_id = findings_manager.insert_finding(
                        scan_session_id=session_id,
                        project_id=project_id,
                        file_path=finding.get('file', ''),
                        secret_type=finding.get('rule', 'unknown'),
                        secret_value=finding.get('secret', ''),
                        context=finding.get('context', ''),
                        severity=finding.get('severity', 'Medium'),
                        line_number=finding.get('line_number'),
                        tool_source='gitleaks',
                        metadata=finding
                    )
                    if finding_id:
                        findings_ids.append(finding_id)

                # Clean up temp file
                os.remove(results_file)
        except Exception as e:
            logger.error(f"Error parsing Gitleaks output: {e}")
        return findings_ids

    def run_multi_scan(self, directory: Path, project_name: str = "multi-scan",
                       scanners: List[str] = None) -> Dict[str, Any]:
        """Run multiple scanners concurrently"""

        if scanners is None:
            scanners = ['custom', 'trufflehog', 'gitleaks']

        # Initialize database
        if not init_database():
            return {'success': False, 'error': 'Database initialization failed'}

        # Initialize Redis
        if not init_redis(host=os.getenv('REDIS_HOST', 'redis'), port=int(os.getenv('REDIS_PORT', 6379))):
            logger.warning("Redis initialization failed - continuing without caching")
        else:
            logger.info("Redis connection initialized successfully")

        # Create project
        project = project_manager.get_project_by_name(project_name)
        if not project:
            project_id = project_manager.create_project(
                name=project_name,
                local_path=str(directory),
                description=f"Multi-scanner scan of {directory}"
            )
        else:
            project_id = project['id']

        # Create scan session
        session_id = scan_session_manager.create_session(
            project_id=project_id,
            scan_type='combined',
            scan_parameters={'scanners': scanners, 'directory': str(directory)}
        )

        if not session_id:
            return {'success': False, 'error': 'Failed to create scan session'}

        # Update project scan time
        project_manager.update_project_scan_time(project_id)

        # Run scanners concurrently
        results = {}
        total_findings = 0

        with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
            future_to_scanner = {
                executor.submit(self.scanners[scanner], directory, project_id, session_id): scanner
                for scanner in scanners if scanner in self.scanners
            }

            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    result = future.result()
                    results[scanner] = result
                    total_findings += result.get('findings', 0)
                    logger.info(f"{scanner} completed: {result}")
                except Exception as e:
                    logger.error(f"{scanner} failed: {e}")
                    results[scanner] = {'success': False, 'findings': 0, 'errors': [str(e)]}

        # Update session with final results
        scan_session_manager.update_session_status(
            session_id=session_id,
            status='completed',
            total_files=0,  # Multi-scanner doesn't track individual files
            total_findings=total_findings
        )

        return {
            'success': True,
            'session_id': session_id,
            'project_id': project_id,
            'results': results,
            'total_findings': total_findings
        }

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Multi-Scanner Orchestrator")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--project", default="multi-scan", help="Project name")
    parser.add_argument("--scanners", nargs='+',
                       choices=['custom', 'trufflehog', 'gitleaks'],
                       default=['custom', 'trufflehog', 'gitleaks'],
                       help="Scanners to run")
    parser.add_argument("--config", help="Configuration file path")

    args = parser.parse_args()

    # Initialize Redis
    if not redis_manager.ping():
        logger.warning("Redis not available - continuing without caching")

    # Run multi-scanner
    orchestrator = MultiScannerOrchestrator()
    result = orchestrator.run_multi_scan(
        directory=Path(args.directory),
        project_name=args.project,
        scanners=args.scanners
    )

    if result['success']:
        print(f"Multi-scan completed successfully!")
        print(f"Session ID: {result['session_id']}")
        print(f"Total findings: {result['total_findings']}")
        for scanner, scanner_result in result['results'].items():
            print(f"{scanner}: {scanner_result.get('findings', 0)} findings")
        return 0
    else:
        print(f"Multi-scan failed: {result.get('error', 'Unknown error')}")
        return 1

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    exit(main())