#!/usr/bin/env python3
"""
SecretSnipe Dashboard Security Audit Script

This script performs comprehensive security checks on the dashboard configuration
and provides recommendations for hardening the deployment.
"""

import json
import os
import sys
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class SecurityAuditor:
    """Security auditor for SecretSnipe dashboard"""

    def __init__(self, config_file: str = "dashboard_security.json"):
        self.config_file = Path(config_file)
        self.issues = []
        self.warnings = []
        self.passed = []

    def load_config(self) -> Dict[str, Any]:
        """Load security configuration"""
        if not self.config_file.exists():
            logger.error(f"Configuration file not found: {self.config_file}")
            return {}

        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            return {}

    def audit_dashboard_config(self, config: Dict[str, Any]) -> None:
        """Audit dashboard configuration"""
        dashboard_config = config.get('dashboard', {})

        # Check host binding
        host = dashboard_config.get('host', '0.0.0.0')
        if host == '0.0.0.0':
            self.issues.append("Dashboard is bound to all interfaces (0.0.0.0) - consider binding to localhost (127.0.0.1) for security")
        else:
            self.passed.append("Dashboard is properly bound to specific interface")

        # Check debug mode
        debug = dashboard_config.get('debug', False)
        if debug:
            self.issues.append("Debug mode is enabled - disable for production")
        else:
            self.passed.append("Debug mode is disabled")

        # Check rate limiting
        rate_limit = dashboard_config.get('rate_limit_enabled', False)
        if not rate_limit:
            self.warnings.append("Rate limiting is disabled - consider enabling to prevent abuse")
        else:
            self.passed.append("Rate limiting is enabled")

        # Check authentication
        auth_enabled = dashboard_config.get('enable_auth', False)
        if not auth_enabled:
            self.warnings.append("Authentication is disabled - consider enabling for production use")
        else:
            self.passed.append("Authentication is enabled")

        # Check HTTPS
        https_enabled = dashboard_config.get('enable_https', False)
        if not https_enabled:
            self.warnings.append("HTTPS is not enabled - consider using HTTPS in production")
        else:
            self.passed.append("HTTPS is enabled")

        # Check CSRF protection
        csrf_enabled = dashboard_config.get('enable_csrf_protection', False)
        if not csrf_enabled:
            self.issues.append("CSRF protection is disabled - enable for security")
        else:
            self.passed.append("CSRF protection is enabled")

        # Check audit logging
        audit_enabled = dashboard_config.get('enable_audit_log', False)
        if not audit_enabled:
            self.warnings.append("Audit logging is disabled - enable for security monitoring")
        else:
            self.passed.append("Audit logging is enabled")

    def audit_file_permissions(self) -> None:
        """Audit file permissions"""
        sensitive_files = [
            'config.json',
            'dashboard_security.json',
            'secretsnipe.log',
            'dashboard_audit.log'
        ]

        for file_path in sensitive_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                # Check if file is world-readable
                if bool(stat.st_mode & 0o004):
                    self.issues.append(f"File {file_path} is world-readable - restrict permissions")
                else:
                    self.passed.append(f"File {file_path} has appropriate permissions")

    def audit_environment_variables(self) -> None:
        """Audit environment variables for sensitive data"""
        sensitive_vars = [
            'POSTGRES_PASSWORD',
            'REDIS_PASSWORD',
            'DASHBOARD_AUTH_PASSWORD',
            'SECRET_KEY'
        ]

        for var in sensitive_vars:
            if os.getenv(var):
                # Check if variable contains sensitive patterns
                value = os.getenv(var)
                if len(value) < 8:
                    self.warnings.append(f"Environment variable {var} is too short - use stronger secrets")
                elif value in ['password', 'admin', '123456', 'secret']:
                    self.issues.append(f"Environment variable {var} contains weak/default value")
                else:
                    self.passed.append(f"Environment variable {var} appears secure")

    def audit_docker_security(self) -> None:
        """Audit Docker security settings"""
        try:
            # Check if running in Docker
            with open('/proc/1/cgroup', 'r') as f:
                if 'docker' in f.read():
                    self.passed.append("Running in Docker container")

                    # Check for security-related environment variables
                    security_env_vars = [
                        'PYTHONHASHSEED',
                        'PYTHONDONTWRITEBYTECODE',
                        'UMASK'
                    ]

                    for var in security_env_vars:
                        if os.getenv(var):
                            self.passed.append(f"Security environment variable {var} is set")
                        else:
                            self.warnings.append(f"Security environment variable {var} is not set")

        except FileNotFoundError:
            self.warnings.append("Not running in Docker - ensure container security measures are in place")

    def generate_report(self) -> str:
        """Generate security audit report"""
        report = []
        report.append("=" * 60)
        report.append("SECRET SNIPE DASHBOARD SECURITY AUDIT REPORT")
        report.append("=" * 60)
        report.append("")

        if self.issues:
            report.append("🚨 CRITICAL ISSUES:")
            for issue in self.issues:
                report.append(f"  • {issue}")
            report.append("")

        if self.warnings:
            report.append("⚠️  WARNINGS:")
            for warning in self.warnings:
                report.append(f"  • {warning}")
            report.append("")

        if self.passed:
            report.append("✅ PASSED CHECKS:")
            for passed in self.passed:
                report.append(f"  • {passed}")
            report.append("")

        # Summary
        total_checks = len(self.issues) + len(self.warnings) + len(self.passed)
        report.append("SUMMARY:")
        report.append(f"  • Total checks: {total_checks}")
        report.append(f"  • Critical issues: {len(self.issues)}")
        report.append(f"  • Warnings: {len(self.warnings)}")
        report.append(f"  • Passed: {len(self.passed)}")

        if self.issues:
            report.append("\n🔴 SECURITY STATUS: COMPROMISED - Address critical issues immediately")
        elif self.warnings:
            report.append("\n🟡 SECURITY STATUS: NEEDS IMPROVEMENT - Address warnings")
        else:
            report.append("\n🟢 SECURITY STATUS: SECURE - All checks passed")

        return "\n".join(report)

    def run_audit(self) -> int:
        """Run complete security audit"""
        logger.info("Starting security audit...")

        config = self.load_config()
        if not config:
            return 1

        self.audit_dashboard_config(config)
        self.audit_file_permissions()
        self.audit_environment_variables()
        self.audit_docker_security()

        report = self.generate_report()
        print(report)

        # Save report to file with proper encoding
        with open('security_audit_report.txt', 'w', encoding='utf-8') as f:
            f.write(report)

        logger.info("Security audit completed. Report saved to security_audit_report.txt")

        # Return exit code based on issues
        return 1 if self.issues else 0

def main():
    """Main entry point"""
    auditor = SecurityAuditor()
    return auditor.run_audit()

if __name__ == "__main__":
    sys.exit(main())