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
import signal
import time
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
        self.running = True
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info("Received SIGTERM; finishing current scan...")
        # Wait for current ThreadPool to complete (up to 30s)
        # For simplicity: set flag to stop new submits, join existing
        self.running = False

    def _get_timeout(self, scanner_name: str) -> Optional[int]:
        """Get timeout value for subprocess calls, None means no timeout"""
        # Check for TruffleHog specific override
        if scanner_name == 'trufflehog' and os.getenv('TRUFFLEHOG_NO_TIMEOUT', 'false').lower() == 'true':
            return None
        # Check environment variable first, then fall back to config
        env_timeout = os.getenv('SCANNER_TIMEOUT_SECONDS')
        if env_timeout is not None:
            try:
                timeout_val = int(env_timeout)
                return None if timeout_val <= 0 else timeout_val
            except ValueError:
                logger.warning(f"Invalid SCANNER_TIMEOUT_SECONDS value: {env_timeout}")
        if os.getenv('UNLIMITED_MODE', 'false').lower() == 'true':
            return None  # Unlimited for very large scans
        
        # Fall back to config value
        timeout = config.scanner.timeout_seconds
        return None if timeout == 0 else timeout

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
        """Run Trufflehog scanner with memory throttling"""
        try:
            # Update progress in Redis
            try:
                from redis_manager import cache_manager
                cache_manager.set('scan_progress', 'trufflehog', 
                    {'status': 'running', 'last_update': time.time()}, ttl_seconds=3600)
            except Exception:
                pass
            
            # Check if trufflehog is available
            result = subprocess.run(['trufflehog', '--version'],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return {'success': False, 'findings': 0, 'errors': ['Trufflehog not available']}

            # Get memory and concurrency limits from config
            max_depth = int(os.getenv('TRUFFLEHOG_MAX_DEPTH', '5'))  # Limit directory depth
            concurrency = int(os.getenv('TRUFFLEHOG_CONCURRENCY', '2'))  # Reduce parallel workers
            memory_limit_mb = int(os.getenv('SCANNER_MEMORY_LIMIT_MB', '512'))  # Memory cap
            
            # Run trufflehog scan with throttling options
            cmd = [
                'trufflehog', 'filesystem',
                '--directory', str(directory),
                '--json',
                '--no-update',  # Disable updater to prevent permission issues
                '--concurrency', str(concurrency),  # Limit parallel workers
            ]
            
            # Run without memory limit - let Docker container limit control memory
            # Previously used resource.setrlimit but it caused crashes with Go runtime
            def set_process_group():
                os.setsid()

            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=self._get_timeout('trufflehog'), 
                                  preexec_fn=set_process_group)

            if result.returncode == 0:
                # Parse JSON output incrementally to reduce memory usage
                findings = self._parse_trufflehog_output_incremental(result.stdout, session_id, project_id)
                # Update Redis with completion
                try:
                    cache_manager.set('scan_progress', 'trufflehog', 
                        {'status': 'completed', 'findings': len(findings), 'last_update': time.time()}, ttl_seconds=3600)
                except Exception:
                    pass
                return {'success': True, 'findings': len(findings), 'errors': []}
            else:
                error_msg = result.stderr if result.stderr else "Unknown error"
                if "memory" in error_msg.lower() or "killed" in error_msg.lower():
                    logger.warning("TruffleHog hit memory limit - consider reducing TRUFFLEHOG_CONCURRENCY or SCANNER_MEMORY_LIMIT_MB")
                return {'success': False, 'findings': 0, 'errors': [error_msg]}

        except subprocess.TimeoutExpired:
            logger.warning("TruffleHog timed out; marking partial success if findings >0")
            return {'success': False, 'findings': 0, 'errors': ['Trufflehog scan timeout']}
        except MemoryError:
            logger.error("TruffleHog caused memory error - reduce TRUFFLEHOG_CONCURRENCY")
            return {'success': False, 'findings': 0, 'errors': ['Memory limit exceeded']}
        except Exception as e:
            logger.error(f"Trufflehog scanner error: {e}")
            return {'success': False, 'findings': 0, 'errors': [str(e)]}

    def _run_gitleaks(self, directory: Path, project_id: str, session_id: str) -> Dict[str, Any]:
        """Run Gitleaks scanner with memory throttling"""
        try:
            # Update progress in Redis
            try:
                from redis_manager import cache_manager
                cache_manager.set('scan_progress', 'gitleaks', 
                    {'status': 'running', 'last_update': time.time()}, ttl_seconds=3600)
            except Exception:
                pass
            
            # Check if gitleaks is available
            result = subprocess.run(['gitleaks', 'version'],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return {'success': False, 'findings': 0, 'errors': ['Gitleaks not available']}

            # Get memory limits from config
            max_file_size_mb = int(os.getenv('GITLEAKS_MAX_FILE_SIZE_MB', '10'))  # Skip files larger than this
            memory_limit_mb = int(os.getenv('SCANNER_MEMORY_LIMIT_MB', '512'))  # Memory cap
            max_depth = int(os.getenv('GITLEAKS_MAX_DEPTH', '10'))  # Directory depth limit
            
            # Create temporary file for results
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', suffix='_gitleaks.json', delete=False) as temp_file:
                temp_results_path = temp_file.name

            # Run gitleaks scan with throttling
            cmd = [
                'gitleaks', 'detect',
                '--source', str(directory),
                '--report-format', 'json',
                '--report-path', temp_results_path,
                '--no-git',  # Allow scanning non-git directories
                '--max-target-megabytes', str(max_file_size_mb)  # Skip large files
            ]
            
            # Run without memory limit - let Docker container limit control memory
            # Previously used resource.setrlimit but it caused crashes with Go runtime
            def set_process_group():
                os.setsid()

            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=self._get_timeout('gitleaks'), 
                                  preexec_fn=set_process_group)

            if result.returncode == 0 or result.returncode == 1:  # Gitleaks returns 1 when findings found
                # Parse results and store findings
                findings = self._parse_gitleaks_output(temp_results_path, session_id, project_id)
                # Update Redis with completion
                try:
                    cache_manager.set('scan_progress', 'gitleaks', 
                        {'status': 'completed', 'findings': len(findings), 'last_update': time.time()}, ttl_seconds=3600)
                except Exception:
                    pass
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
                    
                    # Map detector type to severity
                    detector_name = finding_data.get('detector_name', 'unknown')
                    severity = self._get_trufflehog_severity(detector_name, finding_data.get('verified', False))
                    
                    finding_id = findings_manager.insert_finding(
                        scan_session_id=session_id,
                        project_id=project_id,
                        file_path=finding_data.get('path', ''),
                        secret_type=detector_name,
                        secret_value=finding_data.get('raw', ''),
                        context=finding_data.get('context', ''),
                        severity=severity,
                        line_number=finding_data.get('line_number'),
                        tool_source='trufflehog',
                        metadata=finding_data
                    )
                    if finding_id:
                        findings_ids.append(finding_id)
        except Exception as e:
            logger.error(f"Error parsing Trufflehog output: {e}")
        return findings_ids
    
    def _get_trufflehog_severity(self, detector_name: str, verified: bool) -> str:
        """Map TruffleHog detector types to severity levels.
        
        Verified secrets are automatically Critical.
        Unverified secrets use detector-based mapping.
        """
        # Verified secrets are always critical - they're confirmed active
        if verified:
            return 'Critical'
        
        detector_lower = detector_name.lower()
        
        # Critical - Cloud provider keys, payment systems, high-impact
        critical_detectors = [
            'aws', 'azure', 'gcp', 'google', 'stripe', 'paypal', 'braintree',
            'privatekey', 'private_key', 'rsa', 'ssh', 'pgp', 'certificate',
            'database', 'postgres', 'mysql', 'mongodb', 'redis', 'elasticsearch',
            'openai', 'anthropic', 'huggingface'
        ]
        
        # High - API keys, tokens, webhooks
        high_detectors = [
            'github', 'gitlab', 'bitbucket', 'slack', 'discord', 'twilio',
            'sendgrid', 'mailgun', 'mailchimp', 'npm', 'pypi', 'docker',
            'jwt', 'bearer', 'oauth', 'api_key', 'apikey', 'auth', 'token',
            'secret', 'password', 'credential'
        ]
        
        # Medium - Less critical but still sensitive
        medium_detectors = [
            'webhook', 'url', 'endpoint', 'connection', 'config'
        ]
        
        for detector in critical_detectors:
            if detector in detector_lower:
                return 'Critical'
        
        for detector in high_detectors:
            if detector in detector_lower:
                return 'High'
        
        for detector in medium_detectors:
            if detector in detector_lower:
                return 'Medium'
        
        # Default to High for unknown detectors (conservative)
        return 'High'
    
    def _parse_trufflehog_output_incremental(self, output: str, session_id: str, project_id: str) -> List[str]:
        """Parse Trufflehog JSON output incrementally to reduce memory usage
        
        TruffleHog v3 outputs JSON lines. Log messages have a 'level' field,
        while actual findings have 'SourceMetadata' field.
        """
        findings_ids = []
        max_findings = int(os.getenv('MAX_FINDINGS_PER_SCAN', '10000'))
        parsed_count = 0
        skipped_count = 0
        
        try:
            lines = output.strip().split('\n')
            logger.info(f"Parsing {len(lines)} lines of TruffleHog output")
            
            for idx, line in enumerate(lines):
                if idx >= max_findings:
                    logger.warning(f"Reached max findings limit ({max_findings}), stopping parse")
                    break
                    
                if not line.strip():
                    continue
                    
                try:
                    finding_data = json.loads(line)
                    
                    # Skip log messages (they have 'level' field)
                    if 'level' in finding_data:
                        skipped_count += 1
                        continue
                    
                    # Skip if no SourceMetadata (not a finding)
                    if 'SourceMetadata' not in finding_data:
                        skipped_count += 1
                        continue
                    
                    # Extract file path from SourceMetadata
                    source_meta = finding_data.get('SourceMetadata', {})
                    data = source_meta.get('Data', {})
                    
                    # Try different source types (Filesystem, Git, etc.)
                    file_path = ''
                    if 'Filesystem' in data:
                        file_path = data['Filesystem'].get('file', '')
                    elif 'Git' in data:
                        file_path = data['Git'].get('file', '')
                    else:
                        # Try to find file in any nested structure
                        for key, val in data.items():
                            if isinstance(val, dict) and 'file' in val:
                                file_path = val['file']
                                break
                    
                    # Get other finding details
                    detector_name = finding_data.get('DetectorName', 
                                   finding_data.get('DetectorType', 'unknown'))
                    raw_secret = finding_data.get('Raw', '')
                    verified = finding_data.get('Verified', False)
                    
                    # Skip if no file path (invalid finding)
                    if not file_path:
                        skipped_count += 1
                        continue
                    
                    # Map severity based on detector type and verification status
                    severity = self._get_trufflehog_severity(detector_name, verified)
                    
                    # Insert finding
                    finding_id = findings_manager.insert_finding(
                        scan_session_id=session_id,
                        project_id=project_id,
                        file_path=file_path,
                        secret_type=detector_name,
                        secret_value=raw_secret[:500],  # Truncate large secrets
                        context=str(finding_data.get('ExtraData', ''))[:1000],
                        severity=severity,
                        line_number=None,  # TruffleHog doesn't always provide line numbers
                        tool_source='trufflehog',
                        metadata={'verified': verified}
                    )
                    if finding_id:
                        findings_ids.append(finding_id)
                        parsed_count += 1
                        
                except json.JSONDecodeError:
                    skipped_count += 1
                    continue
                        
                # Periodically clear memory
                if idx % 100 == 0:
                    import gc
                    gc.collect()
            
            logger.info(f"TruffleHog parsing complete: {parsed_count} findings stored, {skipped_count} lines skipped")
                    
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

                logger.info(f"Parsing {len(results)} gitleaks findings from {results_file}")
                
                for finding in results:
                    # Gitleaks uses capitalized field names - log what we're getting
                    file_path = finding.get('File', finding.get('file', ''))
                    rule_id = finding.get('RuleID', finding.get('rule', 'unknown'))
                    secret_value = finding.get('Secret', finding.get('secret', ''))
                    match_value = finding.get('Match', '')  # Sometimes Secret is empty but Match has value
                    description = finding.get('Description', finding.get('description', ''))
                    start_line = finding.get('StartLine', finding.get('line_number'))
                    
                    # Use Match as fallback if Secret is empty
                    if not secret_value and match_value:
                        secret_value = match_value
                    
                    # Log if we're missing critical fields
                    if not file_path:
                        logger.warning(f"Gitleaks finding missing File field: {finding.keys()}")
                    if not secret_value:
                        logger.warning(f"Gitleaks finding missing Secret/Match field: {finding.keys()}")
                    
                    # Get severity from Gitleaks or map from rule ID
                    severity = finding.get('Severity', finding.get('severity'))
                    if not severity:
                        severity = self._get_gitleaks_severity(rule_id)
                    else:
                        # Normalize Gitleaks severity to our format
                        severity = severity.capitalize()
                        if severity not in ['Critical', 'High', 'Medium', 'Low']:
                            severity = self._get_gitleaks_severity(rule_id)
                    
                    finding_id = findings_manager.insert_finding(
                        scan_session_id=session_id,
                        project_id=project_id,
                        file_path=file_path,
                        secret_type=rule_id,
                        secret_value=secret_value,
                        context=description,
                        severity=severity,
                        line_number=start_line,
                        tool_source='gitleaks',
                        metadata=finding
                    )
                    if finding_id:
                        findings_ids.append(finding_id)
                        logger.debug(f"Stored gitleaks finding: {rule_id} in {file_path}")

                # Clean up temp file
                os.remove(results_file)
        except Exception as e:
            logger.error(f"Error parsing Gitleaks output: {e}")
        return findings_ids

    def _get_gitleaks_severity(self, rule_id: str) -> str:
        """Map Gitleaks rule IDs to severity levels."""
        rule_lower = rule_id.lower()
        
        # Critical - Cloud provider keys, private keys, payment systems
        critical_rules = [
            'aws', 'azure', 'gcp', 'google-api', 'private-key', 'privatekey',
            'stripe', 'square', 'paypal', 'braintree', 'adafruit',
            'alibaba', 'algolia', 'authress', 'bittrex', 'clojars',
            'coinbase', 'confluent', 'databricks', 'datadog', 'definednetworking',
            'digitalocean', 'doppler', 'dropbox', 'duffel', 'dynatrace',
            'easypost', 'facebook', 'fastly', 'finicity', 'flutterwave',
            'frameio', 'freshbooks', 'gitter', 'grafana', 'harness',
            'hashicorp', 'heroku', 'hubspot', 'intercom', 'kraken',
            'kucoin', 'launchdarkly', 'linear', 'lob', 'mailgun',
            'mapbox', 'messagebird', 'netlify', 'newrelic', 'nytimes',
            'okta', 'openai', 'pagerduty', 'planetscale', 'plaid',
            'postman', 'prefect', 'pulumi', 'pypi', 'rapidapi',
            'readme', 'rubygems', 'scalingo', 'segment', 'sendbird',
            'sendinblue', 'sentry', 'shippo', 'shopify', 'sidekiq',
            'snyk', 'sourcegraph', 'sqlserver', 'supabase', 'telegram',
            'travisci', 'trello', 'twilio', 'twitter', 'typeform',
            'vault-token', 'vercel', 'webflow', 'yandex', 'zendesk'
        ]
        
        # High - API keys, tokens, webhooks
        high_rules = [
            'github', 'gitlab', 'bitbucket', 'slack', 'discord',
            'npm', 'nuget', 'jwt', 'bearer', 'oauth', 'api-key', 'apikey',
            'generic-api-key', 'secret', 'password', 'credential',
            'sendgrid', 'mailchimp', 'docker', 'kubernetes', 'artifactory',
            'asana', 'atera', 'auth0', 'beamer', 'buildkite', 'buttercms',
            'calendly', 'circleci', 'clickup', 'codecov', 'contentful',
            'crates', 'droneci', 'figma', 'firebase', 'fleetbase',
            'gitea', 'intra42', 'jfrog', 'linenotify', 'localstack',
            'mattermost', 'maxmind', 'mux', 'notion', 'patreon',
            'rollbar', 'sauce', 'sonarcloud', 'sumologic', 'tailscale',
            'tines', 'upcloud', 'vault', 'vault-batch-token', 'wiz'
        ]
        
        # Check Critical rules
        for rule in critical_rules:
            if rule in rule_lower:
                return 'Critical'
        
        # Check High rules  
        for rule in high_rules:
            if rule in rule_lower:
                return 'High'
        
        # Default to Medium for unknown rules
        return 'Medium'

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

        # Run scanners sequentially to avoid memory issues
        results = {}
        total_findings = 0

        # Run in order: custom -> gitleaks -> trufflehog (most memory-intensive last)
        scanner_order = []
        if 'custom' in scanners:
            scanner_order.append('custom')
        if 'gitleaks' in scanners:
            scanner_order.append('gitleaks')
        if 'trufflehog' in scanners:
            scanner_order.append('trufflehog')

        for scanner in scanner_order:
            if scanner in self.scanners and self.running:
                logger.info(f"Starting {scanner} scanner...")
                try:
                    result = self.scanners[scanner](directory, project_id, session_id)
                    results[scanner] = result
                    total_findings += result.get('findings', 0)
                    
                    # Update session progress after each scanner
                    scan_session_manager.update_session_status(session_id, 'in_progress', total_findings=total_findings)
                    logger.info(f"{scanner} completed: {result}")
                    
                    # Force garbage collection between scanners to free memory
                    import gc
                    gc.collect()
                    
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

    # Redis will be initialized inside run_multi_scan - no need to check here
    
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