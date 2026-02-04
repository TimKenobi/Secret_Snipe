"""
Email Manager for SecretSnipe

Provides SMTP email functionality for:
- Sending finding notifications to file owners
- Escalation warnings and notices
- Template-based email generation
- Email delivery tracking and retry logic
"""

import os
import ssl
import json
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from jinja2 import Template, Environment, BaseLoader

from database_manager import db_manager

logger = logging.getLogger(__name__)


@dataclass
class EmailConfig:
    """SMTP configuration settings"""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    from_email: str = ""
    from_name: str = "SecretSnipe Security"
    reply_to_email: str = ""
    is_active: bool = False


@dataclass
class EmailTemplate:
    """Email template definition"""
    template_key: str
    template_name: str
    subject_template: str
    body_template: str
    body_html_template: Optional[str] = None
    description: str = ""
    available_variables: List[str] = None


class EmailManager:
    """Manages email notifications for SecretSnipe"""
    
    def __init__(self):
        self.db = db_manager
        self._config: Optional[EmailConfig] = None
        self._templates_cache: Dict[str, EmailTemplate] = {}
        self._jinja_env = Environment(loader=BaseLoader())
    
    @property
    def config(self) -> EmailConfig:
        """Get current email configuration from database"""
        if self._config is None:
            self._config = self._load_config()
        return self._config
    
    def _load_config(self) -> EmailConfig:
        """Load email configuration from database"""
        try:
            query = """
                SELECT smtp_host, smtp_port, smtp_username, smtp_password,
                       smtp_use_tls, smtp_use_ssl, from_email, from_name,
                       reply_to_email, is_active
                FROM email_config
                WHERE config_name = 'default'
                LIMIT 1
            """
            result = self.db.execute_query(query)
            if result:
                return EmailConfig(**result[0])
            return EmailConfig()
        except Exception as e:
            logger.warning(f"Could not load email config: {e}")
            return EmailConfig()
    
    def reload_config(self):
        """Force reload of configuration"""
        self._config = None
        self._templates_cache = {}
    
    def save_config(self, config: EmailConfig) -> bool:
        """Save email configuration to database"""
        try:
            query = """
                INSERT INTO email_config (
                    config_name, smtp_host, smtp_port, smtp_username, smtp_password,
                    smtp_use_tls, smtp_use_ssl, from_email, from_name, reply_to_email,
                    is_active, updated_at
                ) VALUES (
                    'default', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()
                )
                ON CONFLICT (config_name) DO UPDATE SET
                    smtp_host = EXCLUDED.smtp_host,
                    smtp_port = EXCLUDED.smtp_port,
                    smtp_username = EXCLUDED.smtp_username,
                    smtp_password = EXCLUDED.smtp_password,
                    smtp_use_tls = EXCLUDED.smtp_use_tls,
                    smtp_use_ssl = EXCLUDED.smtp_use_ssl,
                    from_email = EXCLUDED.from_email,
                    from_name = EXCLUDED.from_name,
                    reply_to_email = EXCLUDED.reply_to_email,
                    is_active = EXCLUDED.is_active,
                    updated_at = NOW()
            """
            self.db.execute_update(query, (
                config.smtp_host, config.smtp_port, config.smtp_username,
                config.smtp_password, config.smtp_use_tls, config.smtp_use_ssl,
                config.from_email, config.from_name, config.reply_to_email,
                config.is_active
            ))
            self._config = config
            logger.info("Email configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save email config: {e}")
            return False
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test SMTP connection with current configuration"""
        config = self.config
        if not config.smtp_host:
            return False, "SMTP host not configured"
        
        try:
            if config.smtp_use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(
                    config.smtp_host, config.smtp_port,
                    context=context, timeout=10
                )
            else:
                server = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10)
                if config.smtp_use_tls:
                    server.starttls()
            
            if config.smtp_username and config.smtp_password:
                server.login(config.smtp_username, config.smtp_password)
            
            server.quit()
            
            # Update test status in database
            self._update_test_status(True)
            
            return True, "Connection successful"
        
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
            return False, f"Authentication failed: {str(e)}"
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP connection failed: {e}")
            return False, f"Connection failed: {str(e)}"
        except Exception as e:
            logger.error(f"SMTP test failed: {e}")
            return False, f"Error: {str(e)}"
    
    def _update_test_status(self, success: bool):
        """Update test status in database"""
        try:
            query = """
                UPDATE email_config 
                SET test_successful = %s, last_test_at = NOW()
                WHERE config_name = 'default'
            """
            self.db.execute_update(query, (success,))
        except Exception as e:
            logger.warning(f"Could not update test status: {e}")
    
    def get_template(self, template_key: str) -> Optional[EmailTemplate]:
        """Get email template by key"""
        if template_key in self._templates_cache:
            return self._templates_cache[template_key]
        
        try:
            query = """
                SELECT template_key, template_name, subject_template, body_template,
                       body_html_template, description, available_variables
                FROM email_templates
                WHERE template_key = %s AND is_active = true
            """
            result = self.db.execute_query(query, (template_key,))
            if result:
                template = EmailTemplate(**result[0])
                self._templates_cache[template_key] = template
                return template
            return None
        except Exception as e:
            logger.error(f"Failed to load template {template_key}: {e}")
            return None
    
    def get_all_templates(self) -> List[EmailTemplate]:
        """Get all active email templates"""
        try:
            query = """
                SELECT template_key, template_name, subject_template, body_template,
                       body_html_template, description, available_variables
                FROM email_templates
                WHERE is_active = true
                ORDER BY template_name
            """
            results = self.db.execute_query(query)
            return [EmailTemplate(**r) for r in results]
        except Exception as e:
            logger.error(f"Failed to load templates: {e}")
            return []
    
    def save_template(self, template: EmailTemplate) -> bool:
        """Save or update an email template"""
        try:
            query = """
                INSERT INTO email_templates (
                    template_key, template_name, subject_template, body_template,
                    body_html_template, description, available_variables, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (template_key) DO UPDATE SET
                    template_name = EXCLUDED.template_name,
                    subject_template = EXCLUDED.subject_template,
                    body_template = EXCLUDED.body_template,
                    body_html_template = EXCLUDED.body_html_template,
                    description = EXCLUDED.description,
                    available_variables = EXCLUDED.available_variables,
                    updated_at = NOW()
            """
            self.db.execute_update(query, (
                template.template_key, template.template_name,
                template.subject_template, template.body_template,
                template.body_html_template, template.description,
                template.available_variables
            ))
            self._templates_cache[template.template_key] = template
            return True
        except Exception as e:
            logger.error(f"Failed to save template: {e}")
            return False
    
    def render_template(self, template_key: str, variables: Dict[str, Any]) -> Tuple[str, str, Optional[str]]:
        """Render email template with variables
        
        Returns: (subject, body_text, body_html)
        """
        template = self.get_template(template_key)
        if not template:
            raise ValueError(f"Template not found: {template_key}")
        
        # Render subject
        subject_tpl = self._jinja_env.from_string(template.subject_template)
        subject = subject_tpl.render(**variables)
        
        # Render body
        body_tpl = self._jinja_env.from_string(template.body_template)
        body_text = body_tpl.render(**variables)
        
        # Render HTML body if available
        body_html = None
        if template.body_html_template:
            html_tpl = self._jinja_env.from_string(template.body_html_template)
            body_html = html_tpl.render(**variables)
        
        return subject, body_text, body_html
    
    def send_email(
        self,
        to_email: str,
        to_name: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        finding_id: Optional[str] = None,
        template_key: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send an email
        
        Args:
            to_email: Recipient email address
            to_name: Recipient name
            subject: Email subject
            body_text: Plain text body
            body_html: Optional HTML body
            finding_id: Optional finding ID to link in notifications table
            template_key: Optional template key for logging
            
        Returns:
            (success, message)
        """
        config = self.config
        
        if not config.is_active:
            return False, "Email notifications are disabled"
        
        if not config.smtp_host:
            return False, "SMTP not configured"
        
        # Create message
        if body_html:
            msg = MIMEMultipart('alternative')
            msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
            msg.attach(MIMEText(body_html, 'html', 'utf-8'))
        else:
            msg = MIMEText(body_text, 'plain', 'utf-8')
        
        msg['Subject'] = subject
        msg['From'] = formataddr((config.from_name, config.from_email))
        msg['To'] = formataddr((to_name, to_email))
        
        if config.reply_to_email:
            msg['Reply-To'] = config.reply_to_email
        
        # Log notification before sending
        notification_id = self._log_notification(
            finding_id, template_key, to_email, to_name, subject, body_text, 'pending'
        )
        
        try:
            if config.smtp_use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(
                    config.smtp_host, config.smtp_port,
                    context=context, timeout=30
                )
            else:
                server = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=30)
                if config.smtp_use_tls:
                    server.starttls()
            
            if config.smtp_username and config.smtp_password:
                server.login(config.smtp_username, config.smtp_password)
            
            server.sendmail(config.from_email, [to_email], msg.as_string())
            server.quit()
            
            # Update notification status
            self._update_notification_status(notification_id, 'sent')
            
            logger.info(f"Email sent successfully to {to_email}")
            return True, "Email sent successfully"
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Failed to send email to {to_email}: {error_msg}")
            self._update_notification_status(notification_id, 'failed', error_msg)
            return False, f"Failed to send: {error_msg}"
    
    def send_finding_notification(
        self,
        finding_id: str,
        owner_email: str,
        owner_name: str,
        dashboard_url: str = "http://localhost:8050",
        escalation_days: int = 7
    ) -> Tuple[bool, str]:
        """Send notification about a finding to the file owner"""
        
        # Get finding details
        try:
            query = """
                SELECT f.*, p.name as project_name
                FROM findings f
                LEFT JOIN projects p ON f.project_id = p.id
                WHERE f.id = %s
            """
            result = self.db.execute_query(query, (finding_id,))
            if not result:
                return False, "Finding not found"
            
            finding = result[0]
        except Exception as e:
            return False, f"Database error: {e}"
        
        # Calculate escalation date
        escalation_date = datetime.now() + timedelta(days=escalation_days)
        
        # Prepare template variables
        variables = {
            'owner_name': owner_name,
            'owner_email': owner_email,
            'file_path': finding.get('file_path', ''),
            'line_number': finding.get('line_number', 'N/A'),
            'secret_type': finding.get('secret_type', 'Unknown'),
            'severity': finding.get('severity', 'Medium'),
            'tool_source': finding.get('tool_source', 'custom'),
            'finding_category': finding.get('finding_category', 'uncategorized'),
            'first_seen': str(finding.get('first_seen', '')),
            'proof_content': finding.get('proof_content', finding.get('context', 'N/A')),
            'dashboard_url': f"{dashboard_url}#finding-{finding_id}",
            'escalation_date': escalation_date.strftime('%Y-%m-%d'),
            'project_name': finding.get('project_name', 'Unknown')
        }
        
        try:
            subject, body_text, body_html = self.render_template('finding_notification', variables)
        except Exception as e:
            return False, f"Template error: {e}"
        
        # Send the email
        success, message = self.send_email(
            owner_email, owner_name, subject, body_text, body_html,
            finding_id, 'finding_notification'
        )
        
        # Update finding with notification info
        if success:
            try:
                update_query = """
                    UPDATE findings
                    SET owner_email = %s,
                        assigned_owner = %s,
                        notification_sent_at = NOW(),
                        escalation_date = %s,
                        escalation_status = 'pending'
                    WHERE id = %s
                """
                self.db.execute_update(update_query, (
                    owner_email, owner_name, escalation_date, finding_id
                ))
            except Exception as e:
                logger.warning(f"Could not update finding notification status: {e}")
        
        return success, message
    
    def send_bulk_notifications(
        self,
        finding_ids: List[str],
        owner_email: str,
        owner_name: str = "File Owner",
        dashboard_url: str = "http://localhost:8050",
        escalation_days: int = 7
    ) -> Dict[str, Any]:
        """Send ONE consolidated notification for multiple findings to same owner
        
        Groups findings by file for better readability. Sends a single email
        containing all findings rather than spamming with individual emails.
        
        Returns summary with success status and details
        """
        from collections import defaultdict
        
        results = {
            'success': False,
            'sent': 0,
            'total_findings': len(finding_ids),
            'files_included': 0,
            'error': None
        }
        
        if not finding_ids:
            results['error'] = 'No findings to notify about'
            return results
        
        try:
            # Fetch all finding details
            placeholders = ','.join(['%s'] * len(finding_ids))
            query = f"""
                SELECT f.*, p.name as project_name
                FROM findings f
                LEFT JOIN projects p ON f.project_id = p.id
                WHERE f.id IN ({placeholders})
                ORDER BY f.severity DESC, f.file_path
            """
            findings = self.db.execute_query(query, tuple(finding_ids))
            
            if not findings:
                results['error'] = 'No findings found'
                return results
            
            # Group findings by file for better organization
            findings_by_file = defaultdict(list)
            for f in findings:
                findings_by_file[f.get('file_path', 'Unknown')].append(f)
            
            results['files_included'] = len(findings_by_file)
            
            # Calculate escalation date
            escalation_date = datetime.now() + timedelta(days=escalation_days)
            
            # Build consolidated email content
            severity_counts = defaultdict(int)
            for f in findings:
                severity_counts[f.get('severity', 'Medium')] += 1
            
            # Determine highest severity for subject line
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
            highest_severity = 'Medium'
            for sev in severity_order:
                if severity_counts.get(sev, 0) > 0:
                    highest_severity = sev
                    break
            
            # Build subject
            subject = f"[SecretSnipe] {highest_severity}: {len(findings)} Secret(s) Found in {len(findings_by_file)} File(s)"
            
            # Build HTML body
            body_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color: #dc2626;">🔐 Secret Detection Alert</h2>
            <p>Hello {owner_name or 'Team'},</p>
            <p>SecretSnipe has detected <strong>{len(findings)} potential secret(s)</strong> in <strong>{len(findings_by_file)} file(s)</strong> that require your attention.</p>
            
            <h3>📊 Summary</h3>
            <ul>
            """
            for sev in severity_order:
                if severity_counts.get(sev, 0) > 0:
                    color = {'Critical': '#7f1d1d', 'High': '#dc2626', 'Medium': '#f59e0b', 'Low': '#3b82f6', 'Info': '#6b7280'}.get(sev, '#333')
                    body_html += f'<li><span style="color: {color}; font-weight: bold;">{sev}</span>: {severity_counts[sev]}</li>'
            body_html += "</ul>"
            
            body_html += f"""
            <h3>📁 Findings by File</h3>
            <p style="color: #666; font-size: 0.9em;">Escalation date: {escalation_date.strftime('%Y-%m-%d')} ({escalation_days} days)</p>
            """
            
            for file_path, file_findings in findings_by_file.items():
                body_html += f"""
                <div style="background: #f8f9fa; border-left: 4px solid #dc2626; padding: 10px; margin: 10px 0;">
                    <strong>📄 {file_path}</strong> ({len(file_findings)} finding(s))
                    <ul style="margin: 5px 0;">
                """
                for f in file_findings[:5]:  # Limit to first 5 per file
                    sev_color = {'Critical': '#7f1d1d', 'High': '#dc2626', 'Medium': '#f59e0b', 'Low': '#3b82f6', 'Info': '#6b7280'}.get(f.get('severity', 'Medium'), '#333')
                    body_html += f"""
                    <li>
                        <span style="color: {sev_color};">[{f.get('severity', 'Medium')}]</span>
                        {f.get('secret_type', 'Unknown')} at line {f.get('line_number', 'N/A')}
                    </li>
                    """
                if len(file_findings) > 5:
                    body_html += f"<li><em>... and {len(file_findings) - 5} more findings</em></li>"
                body_html += "</ul></div>"
            
            body_html += f"""
            <h3>🔗 Take Action</h3>
            <p>
                <a href="{dashboard_url}" style="background: #3b82f6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                    View in Dashboard
                </a>
            </p>
            <p style="color: #666; font-size: 0.9em; margin-top: 20px;">
                Please review and resolve these findings before the escalation date.<br>
                If these are false positives, mark them as such in the dashboard.
            </p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="color: #999; font-size: 0.8em;">
                This is an automated message from SecretSnipe Security Scanner.
            </p>
            </body>
            </html>
            """
            
            # Build plain text version
            body_text = f"""
Secret Detection Alert

Hello {owner_name or 'Team'},

SecretSnipe has detected {len(findings)} potential secret(s) in {len(findings_by_file)} file(s).

Summary:
"""
            for sev in severity_order:
                if severity_counts.get(sev, 0) > 0:
                    body_text += f"- {sev}: {severity_counts[sev]}\n"
            
            body_text += "\nFindings by File:\n"
            for file_path, file_findings in findings_by_file.items():
                body_text += f"\n{file_path} ({len(file_findings)} findings):\n"
                for f in file_findings[:5]:
                    body_text += f"  - [{f.get('severity', 'Medium')}] {f.get('secret_type', 'Unknown')} at line {f.get('line_number', 'N/A')}\n"
                if len(file_findings) > 5:
                    body_text += f"  ... and {len(file_findings) - 5} more\n"
            
            body_text += f"""
View in Dashboard: {dashboard_url}

Please review and resolve these findings before {escalation_date.strftime('%Y-%m-%d')}.

This is an automated message from SecretSnipe Security Scanner.
"""
            
            # Send the consolidated email
            success, message = self.send_email(
                owner_email, owner_name, subject, body_text, body_html,
                None, 'bulk_notification'
            )
            
            if success:
                results['success'] = True
                results['sent'] = 1
                
                # Update all findings with notification info
                for finding_id in finding_ids:
                    try:
                        update_query = """
                            UPDATE findings
                            SET owner_email = %s,
                                assigned_owner = %s,
                                notification_sent_at = NOW(),
                                escalation_date = %s,
                                escalation_status = 'pending'
                            WHERE id = %s
                        """
                        self.db.execute_update(update_query, (
                            owner_email, owner_name, escalation_date, finding_id
                        ))
                    except Exception as e:
                        logger.warning(f"Could not update finding {finding_id} notification status: {e}")
            else:
                results['error'] = message
                
        except Exception as e:
            logger.error(f"Failed to send bulk notification: {e}")
            results['error'] = str(e)
        
        return results
    
    def process_escalations(self, dashboard_url: str = "http://localhost:8050") -> Dict[str, Any]:
        """Process findings that have passed their escalation date
        
        Returns summary of escalated findings
        """
        results = {'escalated': 0, 'jira_created': 0, 'errors': []}
        
        try:
            # Find findings past escalation date
            query = """
                SELECT f.id, f.file_path, f.severity, f.owner_email, f.assigned_owner,
                       f.notification_sent_at, f.escalation_date,
                       p.name as project_name
                FROM findings f
                LEFT JOIN projects p ON f.project_id = p.id
                WHERE f.resolution_status = 'open'
                  AND f.escalation_status = 'pending'
                  AND f.escalation_date < NOW()
            """
            findings = self.db.execute_query(query)
            
            for finding in findings:
                try:
                    # Update escalation status
                    update_query = """
                        UPDATE findings
                        SET escalation_status = 'escalated'
                        WHERE id = %s
                    """
                    self.db.execute_update(update_query, (finding['id'],))
                    results['escalated'] += 1
                    
                    # TODO: Create Jira ticket for escalated findings
                    # This would integrate with jira_manager
                    
                except Exception as e:
                    results['errors'].append({
                        'finding_id': str(finding['id']),
                        'error': str(e)
                    })
            
            logger.info(f"Escalation processing complete: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Escalation processing failed: {e}")
            results['errors'].append({'error': str(e)})
            return results
    
    def _log_notification(
        self,
        finding_id: Optional[str],
        template_key: Optional[str],
        recipient_email: str,
        recipient_name: str,
        subject: str,
        body: str,
        status: str
    ) -> Optional[str]:
        """Log email notification to database"""
        try:
            query = """
                INSERT INTO email_notifications (
                    finding_id, template_key, recipient_email, recipient_name,
                    subject, body, status, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                RETURNING id
            """
            result = self.db.execute_query(query, (
                finding_id, template_key, recipient_email, recipient_name,
                subject, body, status
            ))
            return str(result[0]['id']) if result else None
        except Exception as e:
            logger.warning(f"Could not log notification: {e}")
            return None
    
    def _update_notification_status(
        self,
        notification_id: Optional[str],
        status: str,
        error_message: Optional[str] = None
    ):
        """Update notification status in database"""
        if not notification_id:
            return
        
        try:
            if status == 'sent':
                query = """
                    UPDATE email_notifications
                    SET status = %s, sent_at = NOW()
                    WHERE id = %s
                """
                self.db.execute_update(query, (status, notification_id))
            else:
                query = """
                    UPDATE email_notifications
                    SET status = %s, error_message = %s, retry_count = retry_count + 1
                    WHERE id = %s
                """
                self.db.execute_update(query, (status, error_message, notification_id))
        except Exception as e:
            logger.warning(f"Could not update notification status: {e}")
    
    def get_pending_notifications(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending/failed notifications for retry"""
        try:
            query = """
                SELECT * FROM email_notifications
                WHERE status IN ('pending', 'failed')
                  AND retry_count < 3
                ORDER BY created_at
                LIMIT %s
            """
            return self.db.execute_query(query, (limit,))
        except Exception as e:
            logger.error(f"Could not get pending notifications: {e}")
            return []
    
    def get_notification_stats(self) -> Dict[str, Any]:
        """Get email notification statistics"""
        try:
            query = """
                SELECT 
                    status,
                    COUNT(*) as count,
                    MIN(created_at) as oldest,
                    MAX(created_at) as newest
                FROM email_notifications
                GROUP BY status
            """
            results = self.db.execute_query(query)
            
            stats = {
                'by_status': {r['status']: r['count'] for r in results},
                'total': sum(r['count'] for r in results)
            }
            
            # Get today's count
            today_query = """
                SELECT COUNT(*) as count
                FROM email_notifications
                WHERE DATE(created_at) = CURRENT_DATE
            """
            today_result = self.db.execute_query(today_query)
            stats['today'] = today_result[0]['count'] if today_result else 0
            
            return stats
            
        except Exception as e:
            logger.error(f"Could not get notification stats: {e}")
            return {'error': str(e)}


# Global instance
email_manager = EmailManager()


def get_email_config() -> EmailConfig:
    """Get current email configuration"""
    return email_manager.config


def save_email_config(config: EmailConfig) -> bool:
    """Save email configuration"""
    return email_manager.save_config(config)


def test_email_connection() -> Tuple[bool, str]:
    """Test SMTP connection"""
    return email_manager.test_connection()


def send_finding_notification(
    finding_id: str,
    owner_email: str,
    owner_name: str,
    dashboard_url: str = "http://localhost:8050"
) -> Tuple[bool, str]:
    """Send notification about a finding"""
    return email_manager.send_finding_notification(
        finding_id, owner_email, owner_name, dashboard_url
    )
