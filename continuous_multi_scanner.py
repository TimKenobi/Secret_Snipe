"""
Continuous Multi-Scanner Service

Runs custom, TruffleHog, and Gitleaks sequentially on a regular schedule
with deduplication and memory optimization.
"""

import time
import logging
import signal
import sys
from pathlib import Path
from datetime import datetime
import argparse

from run_secret_scanner_pg import MultiScannerOrchestrator
from database_manager import init_database
from redis_manager import init_redis
import os

logger = logging.getLogger(__name__)

class ContinuousMultiScanner:
    """Runs multi-scanner on a schedule"""
    
    def __init__(self, directory: Path, project_name: str, scan_interval_minutes: int = 60):
        self.directory = directory
        self.project_name = project_name
        self.scan_interval_minutes = scan_interval_minutes
        self.running = True
        self.orchestrator = MultiScannerOrchestrator()
        
        # Register signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def start(self):
        """Start continuous scanning"""
        logger.info(f"Starting continuous multi-scanner for {self.directory}")
        logger.info(f"Scan interval: {self.scan_interval_minutes} minutes")
        logger.info("Scanners will run sequentially: custom -> gitleaks -> trufflehog")
        
        # Run initial full scan on startup
        logger.info("=== Running initial full scan on startup ===")
        self._run_scan(scan_number=0)
        logger.info("=== Initial scan completed ===")
        
        scan_count = 0
        
        while self.running:
            scan_count += 1
            self._run_scan(scan_count)
            
            # Calculate sleep time
            if self.running:
                sleep_seconds = self.scan_interval_minutes * 60
                next_scan = datetime.now().timestamp() + sleep_seconds
                next_scan_time = datetime.fromtimestamp(next_scan).strftime('%Y-%m-%d %H:%M:%S')
                logger.info(f"Next scan scheduled for {next_scan_time} (in {self.scan_interval_minutes} minutes)")
                
                # Sleep in small increments to allow graceful shutdown
                for _ in range(sleep_seconds):
                    if not self.running:
                        break
                    time.sleep(1)
        
        logger.info("Continuous multi-scanner stopped")
    
    def _run_scan(self, scan_number: int):
        """Execute a single scan cycle"""
        scan_start = datetime.now()
        
        if scan_number == 0:
            logger.info(f"=== Starting initial scan at {scan_start.strftime('%Y-%m-%d %H:%M:%S')} ===")
        else:
            logger.info(f"=== Starting scan #{scan_number} at {scan_start.strftime('%Y-%m-%d %H:%M:%S')} ===")
        
        try:
            # Run all three scanners sequentially
            # The orchestrator already handles memory optimization and sequential execution
            # Deduplication is handled automatically by the database fingerprinting
            result = self.orchestrator.run_multi_scan(
                directory=self.directory,
                project_name=self.project_name,
                scanners=['custom', 'gitleaks', 'trufflehog']
            )
            
            scan_duration = (datetime.now() - scan_start).total_seconds()
            
            if result['success']:
                scan_label = "Initial scan" if scan_number == 0 else f"Scan #{scan_number}"
                logger.info(f"=== {scan_label} completed successfully in {scan_duration:.1f}s ===")
                logger.info(f"Total findings: {result['total_findings']}")
                
                # Log individual scanner results
                for scanner, scanner_result in result['results'].items():
                    findings = scanner_result.get('findings', 0)
                    success = scanner_result.get('success', False)
                    status = "✓" if success else "✗"
                    logger.info(f"  {status} {scanner}: {findings} findings")
                
            else:
                logger.error(f"=== Scan failed: {result.get('error')} ===")
            
        except Exception as e:
            logger.error(f"Error during scan: {e}", exc_info=True)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Continuous Multi-Scanner Service")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--project", default="multi-scan", help="Project name")
    parser.add_argument("--interval", type=int, default=60, 
                       help="Scan interval in minutes (default: 60)")
    parser.add_argument("--log-level", default="INFO",
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help="Logging level")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Initialize database
    logger.info("Initializing database...")
    if not init_database():
        logger.error("Failed to initialize database")
        return 1
    
    # Initialize Redis
    logger.info("Initializing Redis...")
    redis_host = os.getenv('REDIS_HOST', 'redis')
    redis_port = int(os.getenv('REDIS_PORT', 6379))
    
    if not init_redis(host=redis_host, port=redis_port):
        logger.warning("Redis initialization failed - continuing without caching")
    else:
        logger.info("Redis connection established")
    
    # Create and start continuous scanner
    scanner = ContinuousMultiScanner(
        directory=Path(args.directory),
        project_name=args.project,
        scan_interval_minutes=args.interval
    )
    
    try:
        scanner.start()
        return 0
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
