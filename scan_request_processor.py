"""
Scan Request Processor for SecretSnipe

This module processes scan requests from the dashboard UI.
It can be run as a standalone service or integrated with the existing scanner.

Usage:
    # As standalone processor
    python scan_request_processor.py
    
    # Integrated with existing scanner - import and call process_pending_scans()
    from scan_request_processor import process_pending_scans
    process_pending_scans()
"""

import os
import sys
import time
import logging
import subprocess
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from database_manager import DatabaseManager
from project_manager import project_manager, ScanRequest

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class ScanRequestProcessor:
    """Processes scan requests from the dashboard"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.running = False
        self.current_scan: Optional[ScanRequest] = None
    
    def process_pending_scans(self, single_pass: bool = False):
        """
        Process all pending scan requests.
        
        Args:
            single_pass: If True, process one batch and return. 
                        If False, run continuously.
        """
        self.running = True
        logger.info("Starting scan request processor...")
        
        while self.running:
            try:
                # Get next pending scan
                pending = project_manager.get_pending_scans()
                
                if pending:
                    request = pending[0]  # Process highest priority first
                    logger.info(f"Processing scan request: {request.id} ({request.scan_type})")
                    
                    self.current_scan = request
                    self._process_scan_request(request)
                    self.current_scan = None
                    
                else:
                    if single_pass:
                        logger.info("No pending scans. Single pass complete.")
                        break
                    # No pending scans, wait before checking again
                    time.sleep(30)
                    
            except Exception as e:
                logger.error(f"Error processing scan requests: {e}")
                if single_pass:
                    break
                time.sleep(60)  # Wait longer on error
        
        self.running = False
        logger.info("Scan request processor stopped.")
    
    def _process_scan_request(self, request: ScanRequest):
        """Process a single scan request"""
        try:
            # Mark as running
            project_manager.update_scan_status(request.id, 'running')
            
            # Get directory info
            directory = project_manager.get_directory(request.directory_id)
            if not directory:
                raise ValueError(f"Directory not found: {request.directory_id}")
            
            logger.info(f"Scanning directory: {directory.directory_path} ({request.scan_type})")
            
            # Execute scan based on type
            if request.scan_type == 'full':
                result = self._run_full_scan(directory.directory_path, request)
            elif request.scan_type == 'incremental':
                result = self._run_incremental_scan(directory.directory_path, request)
            elif request.scan_type == 'custom_only':
                result = self._run_custom_scan(directory.directory_path, request)
            elif request.scan_type == 'trufflehog_only':
                result = self._run_trufflehog_scan(directory.directory_path, request)
            elif request.scan_type == 'gitleaks_only':
                result = self._run_gitleaks_scan(directory.directory_path, request)
            else:
                result = self._run_full_scan(directory.directory_path, request)
            
            # Mark as completed
            project_manager.update_scan_status(
                request.id, 
                'completed',
                files_scanned=result.get('files_scanned', 0),
                findings_count=result.get('findings_count', 0)
            )
            
            logger.info(f"Scan completed: {result.get('files_scanned', 0)} files, {result.get('findings_count', 0)} findings")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            project_manager.update_scan_status(
                request.id, 
                'failed',
                error_message=str(e)
            )
    
    def _run_full_scan(self, directory_path: str, request: ScanRequest) -> Dict[str, Any]:
        """Run full scan with all tools"""
        results = {
            'files_scanned': 0,
            'findings_count': 0
        }
        
        # Run custom scanner
        custom_result = self._run_custom_scan(directory_path, request)
        results['files_scanned'] += custom_result.get('files_scanned', 0)
        results['findings_count'] += custom_result.get('findings_count', 0)
        
        # Run TruffleHog
        th_result = self._run_trufflehog_scan(directory_path, request)
        results['findings_count'] += th_result.get('findings_count', 0)
        
        # Run Gitleaks
        gl_result = self._run_gitleaks_scan(directory_path, request)
        results['findings_count'] += gl_result.get('findings_count', 0)
        
        return results
    
    def _run_incremental_scan(self, directory_path: str, request: ScanRequest) -> Dict[str, Any]:
        """Run incremental scan (only changed files)"""
        # This would use file modification times to only scan changed files
        # For now, delegate to full scan with incremental flag
        return self._run_full_scan(directory_path, request)
    
    def _run_custom_scan(self, directory_path: str, request: ScanRequest) -> Dict[str, Any]:
        """Run custom signature scanner"""
        try:
            # Import scanner dynamically to avoid circular imports
            from secret_snipe_pg import SecretScanner
            
            scanner = SecretScanner()
            # Scan with custom signatures
            result = scanner.scan_directory(
                directory_path,
                project_name=f"scan-{request.id[:8]}",
                incremental=True
            )
            
            return {
                'files_scanned': result.get('files_scanned', 0),
                'findings_count': result.get('findings_count', 0)
            }
        except Exception as e:
            logger.error(f"Custom scan failed: {e}")
            return {'files_scanned': 0, 'findings_count': 0}
    
    def _run_trufflehog_scan(self, directory_path: str, request: ScanRequest) -> Dict[str, Any]:
        """Run TruffleHog scanner"""
        try:
            # Run TruffleHog command
            cmd = [
                "trufflehog", "filesystem", directory_path,
                "--json", "--no-update"
            ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            # Count findings from JSON output
            findings_count = 0
            if process.stdout:
                for line in process.stdout.strip().split('\n'):
                    if line.strip() and '"SourceMetadata"' in line:
                        findings_count += 1
            
            return {'findings_count': findings_count}
            
        except subprocess.TimeoutExpired:
            logger.warning("TruffleHog scan timed out")
            return {'findings_count': 0}
        except FileNotFoundError:
            logger.warning("TruffleHog not found - skipping")
            return {'findings_count': 0}
        except Exception as e:
            logger.error(f"TruffleHog scan failed: {e}")
            return {'findings_count': 0}
    
    def _run_gitleaks_scan(self, directory_path: str, request: ScanRequest) -> Dict[str, Any]:
        """Run Gitleaks scanner"""
        try:
            import tempfile
            import json
            
            # Create temp file for results
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                results_file = f.name
            
            cmd = [
                "gitleaks", "detect",
                "--source", directory_path,
                "--report-format", "json",
                "--report-path", results_file,
                "--no-git"
            ]
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600
            )
            
            # Read results
            findings_count = 0
            if os.path.exists(results_file):
                with open(results_file, 'r') as f:
                    try:
                        results = json.load(f)
                        findings_count = len(results) if isinstance(results, list) else 0
                    except json.JSONDecodeError:
                        pass
                os.unlink(results_file)
            
            return {'findings_count': findings_count}
            
        except subprocess.TimeoutExpired:
            logger.warning("Gitleaks scan timed out")
            return {'findings_count': 0}
        except FileNotFoundError:
            logger.warning("Gitleaks not found - skipping")
            return {'findings_count': 0}
        except Exception as e:
            logger.error(f"Gitleaks scan failed: {e}")
            return {'findings_count': 0}
    
    def stop(self):
        """Stop the processor"""
        self.running = False
        logger.info("Stopping scan request processor...")


def process_pending_scans(single_pass: bool = True):
    """Convenience function to process pending scans"""
    processor = ScanRequestProcessor()
    processor.process_pending_scans(single_pass=single_pass)


if __name__ == "__main__":
    # Run as standalone processor
    processor = ScanRequestProcessor()
    
    try:
        # Check for single-pass mode
        single_pass = "--once" in sys.argv
        processor.process_pending_scans(single_pass=single_pass)
    except KeyboardInterrupt:
        processor.stop()
