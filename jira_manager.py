"""
Jira Integration Manager for SecretSnipe

Provides functionality to create Jira tickets from security findings.
Supports both Jira Cloud and Jira Server/Data Center.
"""

import json
import logging
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass

from config import config

logger = logging.getLogger(__name__)


@dataclass
class JiraTicket:
    """Represents a Jira ticket to be created"""
    summary: str
    description: str
    project_key: str
    issue_type: str
    priority: str
    labels: List[str]
    custom_fields: Dict[str, Any] = None
    
    def to_jira_payload(self) -> Dict[str, Any]:
        """Convert to Jira API payload format"""
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": self.summary,
                "description": self.description,
                "issuetype": {"name": self.issue_type},
                "labels": self.labels
            }
        }
        
        # Only add priority if it's a valid string (some Jira configs reject invalid priorities)
        if self.priority and isinstance(self.priority, str) and self.priority.strip():
            payload["fields"]["priority"] = {"name": self.priority.strip()}
        
        # Add custom fields if provided
        if self.custom_fields:
            for field_id, value in self.custom_fields.items():
                payload["fields"][field_id] = value
        
        return payload


class JiraManager:
    """Manages Jira API interactions for creating security tickets"""
    
    def __init__(self):
        self.config = config.jira
        self._session = None
    
    @property
    def is_configured(self) -> bool:
        """Check if Jira is properly configured"""
        return bool(
            self.config.enabled and
            self.config.server_url and
            self.config.username and
            self.config.api_token and
            self.config.project_key
        )
    
    @property
    def session(self) -> requests.Session:
        """Get or create authenticated session"""
        if self._session is None:
            self._session = requests.Session()
            self._session.auth = (self.config.username, self.config.api_token)
            self._session.headers.update({
                "Content-Type": "application/json",
                "Accept": "application/json"
            })
        return self._session
    
    def test_connection(self) -> Dict[str, Any]:
        """Test Jira connection and return server info"""
        if not self.is_configured:
            return {
                "success": False,
                "error": "Jira is not configured. Please set server URL, credentials, and project key."
            }
        
        try:
            url = f"{self.config.server_url.rstrip('/')}/rest/api/2/myself"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                user_info = response.json()
                return {
                    "success": True,
                    "user": user_info.get("displayName", user_info.get("name")),
                    "email": user_info.get("emailAddress"),
                    "server": self.config.server_url
                }
            elif response.status_code == 401:
                return {
                    "success": False,
                    "error": "Authentication failed. Check username and API token."
                }
            else:
                return {
                    "success": False,
                    "error": f"Connection failed with status {response.status_code}: {response.text}"
                }
        except requests.exceptions.RequestException as e:
            logger.error(f"Jira connection test failed: {e}")
            return {
                "success": False,
                "error": f"Connection error: {str(e)}"
            }
    
    def get_projects(self) -> List[Dict[str, str]]:
        """Get list of available Jira projects"""
        if not self.is_configured:
            return []
        
        try:
            url = f"{self.config.server_url.rstrip('/')}/rest/api/2/project"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                projects = response.json()
                return [
                    {"key": p["key"], "name": p["name"]}
                    for p in projects
                ]
            return []
        except Exception as e:
            logger.error(f"Failed to get Jira projects: {e}")
            return []
    
    def get_issue_types(self, project_key: str = None) -> List[str]:
        """Get available issue types for a project"""
        if not self.is_configured:
            return []
        
        project_key = project_key or self.config.project_key
        
        try:
            url = f"{self.config.server_url.rstrip('/')}/rest/api/2/project/{project_key}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                project = response.json()
                return [it["name"] for it in project.get("issueTypes", [])]
            return ["Task", "Bug", "Story"]  # Default fallback
        except Exception as e:
            logger.error(f"Failed to get issue types: {e}")
            return ["Task", "Bug", "Story"]
    
    def get_priorities(self) -> List[str]:
        """Get available Jira priorities"""
        if not self.is_configured:
            return []
        
        try:
            url = f"{self.config.server_url.rstrip('/')}/rest/api/2/priority"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                priorities = response.json()
                return [p["name"] for p in priorities]
            return ["Highest", "High", "Medium", "Low", "Lowest"]
        except Exception as e:
            logger.error(f"Failed to get priorities: {e}")
            return ["Highest", "High", "Medium", "Low", "Lowest"]
    
    def create_ticket_from_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Jira ticket from a security finding"""
        if not self.is_configured:
            return {
                "success": False,
                "error": "Jira is not configured"
            }
        
        # Map severity to Jira priority - but don't include if we can't validate it
        severity = finding.get("severity", "Medium")
        priority = None  # Default to no priority (let Jira use default)
        
        # Try to get valid priorities and use one if the mapping is valid
        try:
            valid_priorities = self.get_priorities()
            mapped_priority = self.config.priority_mapping.get(severity, self.config.default_priority)
            if mapped_priority in valid_priorities:
                priority = mapped_priority
            else:
                logger.warning(f"Priority '{mapped_priority}' not found in Jira. Available: {valid_priorities}")
        except Exception as e:
            logger.warning(f"Could not validate priority: {e}")
        
        # Build ticket summary
        secret_type = finding.get("secret_type", "Unknown Secret")
        file_path = finding.get("file_path", "Unknown File")
        # Truncate file path for summary if too long
        if len(file_path) > 60:
            file_path_display = "..." + file_path[-57:]
        else:
            file_path_display = file_path
        
        summary = f"[{severity}] Secret Detected: {secret_type} in {file_path_display}"
        
        # Truncate summary if too long (Jira limit is 255)
        if len(summary) > 250:
            summary = summary[:247] + "..."
        
        # Build detailed description
        description = self._build_ticket_description(finding)
        
        # Create ticket object
        ticket = JiraTicket(
            summary=summary,
            description=description,
            project_key=self.config.project_key,
            issue_type=self.config.issue_type,
            priority=priority,
            labels=self.config.labels.copy(),
            custom_fields=self.config.custom_fields
        )
        
        # Add severity as label
        ticket.labels.append(f"severity-{severity.lower()}")
        
        return self._create_ticket(ticket)
    
    def create_bulk_tickets(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create multiple Jira tickets from findings"""
        results = {
            "success_count": 0,
            "failed_count": 0,
            "created_tickets": [],
            "errors": []
        }
        
        for finding in findings:
            result = self.create_ticket_from_finding(finding)
            if result.get("success"):
                results["success_count"] += 1
                results["created_tickets"].append({
                    "key": result.get("key"),
                    "url": result.get("url"),
                    "finding_id": finding.get("id")
                })
            else:
                results["failed_count"] += 1
                results["errors"].append({
                    "finding_id": finding.get("id"),
                    "error": result.get("error")
                })
        
        return results
    
    def create_tickets_by_file(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create ONE Jira ticket per file, consolidating all findings in that file.
        
        This is useful when you want to create fewer tickets, with each ticket
        containing all secrets found in a single file.
        """
        from collections import defaultdict
        
        results = {
            "success_count": 0,
            "failed_count": 0,
            "created_tickets": [],
            "errors": [],
            "files_processed": 0
        }
        
        # Group findings by file path
        findings_by_file = defaultdict(list)
        for finding in findings:
            file_path = finding.get('file_path', 'Unknown')
            findings_by_file[file_path].append(finding)
        
        results["files_processed"] = len(findings_by_file)
        
        for file_path, file_findings in findings_by_file.items():
            try:
                # Determine highest severity among findings in this file
                severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
                max_severity = max(file_findings, key=lambda f: severity_order.get(f.get('severity', 'Medium'), 2))
                highest_severity = max_severity.get('severity', 'Medium')
                
                # Get unique secret types
                secret_types = list(set(f.get('secret_type', 'Unknown') for f in file_findings))
                secret_types_str = ', '.join(secret_types[:3])
                if len(secret_types) > 3:
                    secret_types_str += f" (+{len(secret_types) - 3} more)"
                
                # Build summary
                file_display = file_path[-57:] if len(file_path) > 60 else file_path
                if len(file_path) > 60:
                    file_display = "..." + file_display
                
                summary = f"[{highest_severity}] {len(file_findings)} Secret(s) in {file_display}"
                if len(summary) > 250:
                    summary = summary[:247] + "..."
                
                # Build consolidated description
                description = self._build_file_ticket_description(file_path, file_findings, highest_severity)
                
                # Create ticket
                priority = self._severity_to_priority(highest_severity)
                ticket = JiraTicket(
                    summary=summary,
                    description=description,
                    project_key=self.config.project_key,
                    issue_type=self.config.issue_type,
                    priority=priority,
                    labels=self.config.labels.copy(),
                    custom_fields=self.config.custom_fields
                )
                ticket.labels.append(f"severity-{highest_severity.lower()}")
                ticket.labels.append("multi-secret-file")
                
                result = self._create_ticket(ticket)
                
                if result.get("success"):
                    results["success_count"] += 1
                    results["created_tickets"].append({
                        "key": result.get("key"),
                        "url": result.get("url"),
                        "file_path": file_path,
                        "finding_count": len(file_findings),
                        "finding_ids": [f.get('id') for f in file_findings]
                    })
                    
                    # Link ticket to all findings in this file
                    for finding in file_findings:
                        if finding.get('id'):
                            self.link_ticket_to_finding(finding['id'], result.get("key"), result.get("url"))
                else:
                    results["failed_count"] += 1
                    results["errors"].append({
                        "file_path": file_path,
                        "error": result.get("error")
                    })
                    
            except Exception as e:
                logger.error(f"Error creating ticket for file {file_path}: {e}")
                results["failed_count"] += 1
                results["errors"].append({
                    "file_path": file_path,
                    "error": str(e)
                })
        
        return results
    
    def _build_file_ticket_description(self, file_path: str, findings: List[Dict[str, Any]], highest_severity: str) -> str:
        """Build a Jira ticket description for multiple findings in a single file"""
        from datetime import datetime
        
        lines = [
            "h2. Security Findings Summary",
            "",
            f"*File:* {{noformat}}{file_path}{{noformat}}",
            f"*Total Secrets Found:* {len(findings)}",
            f"*Highest Severity:* {highest_severity}",
            "",
            "h2. Detected Secrets",
            ""
        ]
        
        # Group findings by secret type for cleaner display
        from collections import Counter
        severity_counts = Counter(f.get('severity', 'Unknown') for f in findings)
        type_counts = Counter(f.get('secret_type', 'Unknown') for f in findings)
        
        lines.append("h3. Severity Breakdown")
        lines.append("||Severity||Count||")
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if severity_counts.get(sev, 0) > 0:
                lines.append(f"|{sev}|{severity_counts[sev]}|")
        
        lines.append("")
        lines.append("h3. Secret Types Found")
        lines.append("||Type||Count||")
        for secret_type, count in type_counts.most_common(10):
            lines.append(f"|{secret_type}|{count}|")
        
        lines.append("")
        lines.append("h2. Finding Details")
        lines.append("")
        
        # List each finding (limit to first 20 to avoid huge tickets)
        for i, finding in enumerate(findings[:20], 1):
            secret_type = finding.get('secret_type', 'Unknown')
            severity = finding.get('severity', 'Unknown')
            line_num = finding.get('line_number', 'N/A')
            tool = finding.get('tool_source', 'unknown')
            context = finding.get('context', '')[:200]
            
            # Mask secret value
            secret_value = finding.get('secret_value', '')
            if len(secret_value) > 8:
                masked = secret_value[:4] + "*" * min(len(secret_value) - 8, 16) + secret_value[-4:]
            else:
                masked = "*" * len(secret_value) if secret_value else "N/A"
            
            lines.append(f"h4. Finding #{i}: {secret_type}")
            lines.append(f"* *Severity:* {severity}")
            lines.append(f"* *Line:* {line_num}")
            lines.append(f"* *Tool:* {tool}")
            lines.append(f"* *Secret (masked):* {{noformat}}{masked[:50]}{{noformat}}")
            if context:
                lines.append(f"* *Context:* {context}")
            lines.append("")
        
        if len(findings) > 20:
            lines.append(f"_... and {len(findings) - 20} more findings. See dashboard for full details._")
            lines.append("")
        
        # Remediation guidance
        lines.extend([
            "h2. Recommended Actions",
            "# Rotate ALL exposed credentials immediately",
            "# Remove secrets from the file",
            "# Use environment variables or a secrets manager",
            "# Review git history for these secrets",
            "# Audit access logs for unauthorized usage",
            "",
            "----",
            f"_Generated by SecretSnipe on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        ])
        
        return "\n".join(lines)

    def _build_ticket_description(self, finding: Dict[str, Any]) -> str:
        """Build a detailed Jira ticket description from a finding"""
        # Use Jira markup format
        lines = [
            "h2. Security Finding Details",
            "",
            f"*Severity:* {finding.get('severity', 'Unknown')}",
            f"*Secret Type:* {finding.get('secret_type', 'Unknown')}",
            f"*Tool Source:* {finding.get('tool_source', 'custom')}",
            f"*First Detected:* {finding.get('first_seen', 'Unknown')}",
            "",
            "h3. Location",
            f"*File Path:* {{noformat}}{finding.get('file_path', 'Unknown')}{{noformat}}",
        ]
        
        if finding.get('line_number'):
            lines.append(f"*Line Number:* {finding.get('line_number')}")
        
        # Add context (code snippet)
        context = finding.get('context', '')
        if context:
            lines.extend([
                "",
                "h3. Code Context",
                "{code}",
                context[:500] + ("..." if len(context) > 500 else ""),
                "{code}"
            ])
        
        # Add masked secret value for reference
        secret_value = finding.get('secret_value', '')
        if secret_value:
            # Mask the middle of the secret
            if len(secret_value) > 8:
                masked = secret_value[:4] + "*" * (len(secret_value) - 8) + secret_value[-4:]
            else:
                masked = "*" * len(secret_value)
            lines.extend([
                "",
                "h3. Detected Secret (Masked)",
                f"{{noformat}}{masked}{{noformat}}"
            ])
        
        # Add remediation guidance
        lines.extend([
            "",
            "h3. Recommended Actions",
            "# Rotate the exposed credential immediately",
            "# Remove the secret from the file",
            "# Use environment variables or a secrets manager",
            "# Review git history for the same secret",
            "# Check for unauthorized access using the exposed credential",
            "",
            "----",
            f"_Generated by SecretSnipe on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        ])
        
        return "\n".join(lines)
    
    def _create_ticket(self, ticket: JiraTicket) -> Dict[str, Any]:
        """Create a ticket in Jira"""
        try:
            url = f"{self.config.server_url.rstrip('/')}/rest/api/2/issue"
            payload = ticket.to_jira_payload()
            
            response = self.session.post(url, json=payload, timeout=30)
            
            if response.status_code in (200, 201):
                result = response.json()
                issue_key = result.get("key")
                issue_url = f"{self.config.server_url.rstrip('/')}/browse/{issue_key}"
                
                logger.info(f"Created Jira ticket: {issue_key}")
                return {
                    "success": True,
                    "key": issue_key,
                    "id": result.get("id"),
                    "url": issue_url
                }
            else:
                error_msg = response.text
                try:
                    error_data = response.json()
                    if "errors" in error_data:
                        error_msg = str(error_data["errors"])
                    elif "errorMessages" in error_data:
                        error_msg = ", ".join(error_data["errorMessages"])
                except:
                    pass
                
                logger.error(f"Failed to create Jira ticket: {error_msg}")
                return {
                    "success": False,
                    "error": f"Failed to create ticket: {error_msg}"
                }
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Jira API error: {e}")
            return {
                "success": False,
                "error": f"API error: {str(e)}"
            }


# Global instance
jira_manager = JiraManager()

# Path for persisting Jira configuration (uses mounted volume in Docker)
# /app/jira_config is a named volume that persists across container restarts
JIRA_CONFIG_DIR = Path("/app/jira_config") if Path("/app/jira_config").exists() else Path(".")
JIRA_CONFIG_FILE = JIRA_CONFIG_DIR / "jira_config.json"


def load_jira_config():
    """Load Jira configuration from file if it exists"""
    global jira_manager
    
    if JIRA_CONFIG_FILE.exists():
        try:
            with open(JIRA_CONFIG_FILE, 'r') as f:
                saved_config = json.load(f)
            
            if saved_config.get('server_url'):
                config.jira.server_url = saved_config['server_url']
                config.jira.enabled = True
            if saved_config.get('username'):
                config.jira.username = saved_config['username']
            if saved_config.get('api_token'):
                config.jira.api_token = saved_config['api_token']
            if saved_config.get('project_key'):
                config.jira.project_key = saved_config['project_key']
            if saved_config.get('issue_type'):
                config.jira.issue_type = saved_config['issue_type']
            if saved_config.get('labels'):
                config.jira.labels = saved_config['labels']
            
            # Reset session to use loaded credentials
            jira_manager._session = None
            logger.info(f"Loaded Jira configuration for project: {config.jira.project_key}")
            return True
        except Exception as e:
            logger.warning(f"Could not load Jira config: {e}")
    return False


def save_jira_config():
    """Save current Jira configuration to file"""
    try:
        saved_config = {
            'server_url': config.jira.server_url,
            'username': config.jira.username,
            'api_token': config.jira.api_token,
            'project_key': config.jira.project_key,
            'issue_type': config.jira.issue_type,
            'labels': config.jira.labels
        }
        with open(JIRA_CONFIG_FILE, 'w') as f:
            json.dump(saved_config, f, indent=2)
        logger.info(f"Saved Jira configuration to {JIRA_CONFIG_FILE}")
        return True
    except Exception as e:
        logger.error(f"Could not save Jira config: {e}")
        return False


def update_jira_config(server_url: str = None, username: str = None, 
                       api_token: str = None, project_key: str = None,
                       issue_type: str = None, labels: List[str] = None) -> Dict[str, Any]:
    """Update Jira configuration at runtime and persist to file"""
    global jira_manager
    
    if server_url is not None:
        config.jira.server_url = server_url
        config.jira.enabled = bool(server_url)
    if username is not None:
        config.jira.username = username
    if api_token is not None:
        config.jira.api_token = api_token
    if project_key is not None:
        config.jira.project_key = project_key
    if issue_type is not None:
        config.jira.issue_type = issue_type
    if labels is not None:
        config.jira.labels = labels
    
    # Reset session to use new credentials
    jira_manager._session = None
    
    # Persist configuration to file
    save_jira_config()
    
    # Test the new configuration
    return jira_manager.test_connection()


# Load saved configuration on module import
load_jira_config()
