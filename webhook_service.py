"""
Webhook Service for SecretSnipe

Processes webhook notifications for severe findings and delivers them
to configured endpoints with retry logic and queue management.
"""

import time
import logging
import requests
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

from database_manager import (
    db_manager, findings_manager, init_database
)
from redis_manager import redis_manager, init_redis
import redis_manager as redis_module
from config import config

logger = logging.getLogger(__name__)

class WebhookProcessor:
    """Processes webhook notifications"""

    def __init__(self):
        self.running = False
        self.executor = ThreadPoolExecutor(max_workers=5)

    def start(self):
        """Start the webhook processor"""
        self.running = True
        logger.info("Webhook processor started")

        # Start worker threads for each webhook config
        webhook_configs = self._get_webhook_configs()
        for config in webhook_configs:
            thread = threading.Thread(
                target=self._process_webhook_queue,
                args=(config['id'],),
                daemon=True
            )
            thread.start()

    def stop(self):
        """Stop the webhook processor"""
        self.running = False
        self.executor.shutdown(wait=True)
        logger.info("Webhook processor stopped")

    def _get_webhook_configs(self) -> List[Dict[str, Any]]:
        """Get all active webhook configurations"""
        query = "SELECT * FROM webhook_configs WHERE is_active = true"
        return db_manager.execute_query(query)

    def _process_webhook_queue(self, webhook_config_id: str):
        """Process webhook queue for a specific configuration"""
        logger.info(f"Started processing queue for webhook {webhook_config_id}")

        while self.running:
            try:
                # Get next notification from queue
                notification = redis_module.notification_queue.get_next_notification(webhook_config_id)

                if notification:
                    self._deliver_notification(webhook_config_id, notification)
                else:
                    # No notifications in queue, wait before checking again
                    time.sleep(5)

            except Exception as e:
                logger.error(f"Error processing webhook queue {webhook_config_id}: {e}")
                time.sleep(10)  # Wait longer on error

    def _deliver_notification(self, webhook_config_id: str, notification: Dict[str, Any]):
        """Deliver a webhook notification"""
        try:
            # Get webhook configuration
            webhook_config = self._get_webhook_config(webhook_config_id)
            if not webhook_config:
                logger.error(f"Webhook config {webhook_config_id} not found")
                return

            finding_data = notification['finding_data']
            attempts = notification.get('attempts', 0)

            # Prepare webhook payload
            payload = self._prepare_payload(finding_data, webhook_config)

            # Attempt delivery
            success = self._send_webhook(webhook_config, payload)

            if success:
                # Log successful delivery
                self._log_delivery(webhook_config_id, finding_data.get('id'), 'sent', payload, None)
                logger.info(f"Webhook delivered successfully for finding {finding_data.get('id')}")
            else:
                attempts += 1
                if attempts < webhook_config.get('max_attempts', 3):
                    # Re-queue for retry
                    notification['attempts'] = attempts
                    redis_module.notification_queue.queue_notification(webhook_config_id, notification)
                    logger.warning(f"Webhook delivery failed, re-queued (attempt {attempts})")
                else:
                    # Max attempts reached, log failure
                    self._log_delivery(webhook_config_id, finding_data.get('id'), 'failed', payload,
                                     f"Max retry attempts ({attempts}) exceeded")
                    logger.error(f"Webhook delivery failed permanently after {attempts} attempts")

        except Exception as e:
            logger.error(f"Error delivering webhook notification: {e}")

    def _get_webhook_config(self, config_id: str) -> Optional[Dict[str, Any]]:
        """Get webhook configuration by ID"""
        query = "SELECT * FROM webhook_configs WHERE id = %s"
        result = db_manager.execute_query(query, (config_id,))
        return dict(result[0]) if result else None

    def _prepare_payload(self, finding_data: Dict[str, Any], webhook_config: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare webhook payload with Teams Adaptive Card format"""
        severity = finding_data.get('severity', 'Unknown')
        secret_type = finding_data.get('secret_type', 'Unknown')
        file_path = finding_data.get('file_path', 'Unknown')
        tool_source = finding_data.get('tool_source', 'Unknown')
        
        # Determine severity color and icon
        if severity == 'Critical':
            color = 'attention'
            severity_icon = '🔴'
        elif severity == 'High':
            color = 'warning'
            severity_icon = '🟠'
        elif severity == 'Medium':
            color = 'good'
            severity_icon = '🟡'
        else:
            color = 'default'
            severity_icon = '⚪'
            
        # Create Teams Adaptive Card payload
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [
                            {
                                "type": "Container",
                                "items": [
                                    {
                                        "type": "ColumnSet",
                                        "columns": [
                                            {
                                                "type": "Column",
                                                "items": [
                                                    {
                                                        "type": "Image",
                                                        "url": "https://raw.githubusercontent.com/microsoft/fluentui-system-icons/main/assets/Shield/SVG/ic_fluent_shield_error_24_filled.svg",
                                                        "size": "Medium"
                                                    }
                                                ],
                                                "width": "auto"
                                            },
                                            {
                                                "type": "Column",
                                                "items": [
                                                    {
                                                        "type": "TextBlock",
                                                        "text": f"🔒 SecretSnipe Alert: {severity_icon} {severity} Secret Detected",
                                                        "weight": "Bolder",
                                                        "size": "Large",
                                                        "color": color
                                                    },
                                                    {
                                                        "type": "TextBlock",
                                                        "text": f"**Secret Type:** {secret_type}",
                                                        "wrap": True
                                                    },
                                                    {
                                                        "type": "TextBlock", 
                                                        "text": f"**File:** `{file_path}`",
                                                        "wrap": True
                                                    },
                                                    {
                                                        "type": "TextBlock",
                                                        "text": f"**Scanner:** {tool_source.title()}",
                                                        "wrap": True
                                                    },
                                                    {
                                                        "type": "TextBlock",
                                                        "text": f"**First Detected:** {finding_data.get('first_seen', 'Unknown')}",
                                                        "wrap": True,
                                                        "size": "Small"
                                                    }
                                                ],
                                                "width": "stretch"
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "type": "Container",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "**Context:**",
                                        "weight": "Bolder"
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": f"```\n{finding_data.get('context', 'No context available')[:200]}...\n```",
                                        "wrap": True,
                                        "fontType": "Monospace"
                                    }
                                ],
                                "style": "emphasis"
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.OpenUrl",
                                "title": "🔍 View in Dashboard",
                                "url": "http://localhost:8050"
                            },
                            {
                                "type": "Action.OpenUrl", 
                                "title": "📚 Security Guidelines",
                                "url": "https://owasp.org/www-project-top-ten/"
                            }
                        ],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.3"
                    }
                }
            ]
        }

    def _send_webhook(self, webhook_config: Dict[str, Any], payload: Dict[str, Any]) -> bool:
        """Send webhook to endpoint"""
        try:
            headers = webhook_config.get('headers', {})
            headers['Content-Type'] = 'application/json'

            # Add authentication if configured
            auth_config = webhook_config.get('auth_config', {})
            if auth_config.get('type') == 'bearer':
                headers['Authorization'] = f"Bearer {auth_config.get('token')}"

            response = requests.post(
                webhook_config['url'],
                json=payload,
                headers=headers,
                timeout=webhook_config.get('timeout_seconds', 30)
            )

            return response.status_code < 400

        except requests.RequestException as e:
            logger.error(f"Webhook request failed: {e}")
            return False

    def _log_delivery(self, webhook_config_id: str, finding_id: str,
                     status: str, request_payload: Dict[str, Any],
                     error_message: Optional[str]):
        """Log webhook delivery"""
        query = """
            INSERT INTO webhook_deliveries
            (webhook_config_id, finding_id, status, request_payload, error_message)
            VALUES (%s, %s, %s, %s, %s)
        """
        db_manager.execute_update(query, (
            webhook_config_id, finding_id, status,
            json.dumps(request_payload), error_message
        ))

    def queue_notification(self, webhook_config_id: str, finding_data: Dict[str, Any]):
        """Queue a notification for delivery"""
        redis_module.notification_queue.queue_notification(webhook_config_id, finding_data)

def check_for_new_findings():
    """Check for new findings that need webhook notifications"""
    try:
        # Get findings that need notifications (high/critical severity, created recently)
        query = """
            SELECT f.*, p.name as project_name, ss.scan_type
            FROM findings f
            JOIN projects p ON f.project_id = p.id
            JOIN scan_sessions ss ON f.scan_session_id = ss.id
            WHERE f.severity IN ('Critical', 'High')
            AND f.resolution_status = 'open'
            AND f.first_seen > NOW() - INTERVAL '1 hour'
        """

        new_findings = db_manager.execute_query(query)

        # Get active webhook configs
        webhook_configs = db_manager.execute_query(
            "SELECT * FROM webhook_configs WHERE is_active = true"
        )

        # Queue notifications for each finding
        processor = WebhookProcessor()
        for finding in new_findings:
            for webhook_config in webhook_configs:
                # Check if finding matches webhook trigger conditions
                if _matches_webhook_trigger(finding, webhook_config):
                    # Convert finding to JSON-serializable format
                    serializable_finding = _make_json_serializable(dict(finding))
                    processor.queue_notification(webhook_config['id'], serializable_finding)

    except Exception as e:
        logger.error(f"Error checking for new findings: {e}")

def _make_json_serializable(obj: Any) -> Any:
    """Convert database objects to JSON-serializable types"""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: _make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_make_json_serializable(item) for item in obj]
    else:
        return obj

def _matches_webhook_trigger(finding: Dict[str, Any], webhook_config: Dict[str, Any]) -> bool:
    """Check if finding matches webhook trigger conditions"""
    # Check severity
    trigger_severities = webhook_config.get('trigger_on_severity', [])
    if finding['severity'] not in trigger_severities:
        return False

    # Check tool source
    trigger_tools = webhook_config.get('trigger_on_tools', [])
    if trigger_tools and finding['tool_source'] not in trigger_tools:
        return False

    return True

def main():
    """Main webhook service"""
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Initialize database
    if not init_database():
        logger.error("Failed to initialize database")
        return 1

    # Initialize Redis with configuration
    redis_host = config.redis.host
    redis_port = config.redis.port
    redis_password = config.redis.password

    if not init_redis(host=redis_host, port=redis_port, password=redis_password):
        logger.error("Failed to initialize Redis")
        return 1

    logger.info("Webhook service starting...")

    # Start webhook processor
    processor = WebhookProcessor()
    processor.start()

    try:
        # Main loop - periodically check for new findings
        while True:
            check_for_new_findings()
            time.sleep(60)  # Check every minute

    except KeyboardInterrupt:
        logger.info("Webhook service stopping...")
        processor.stop()

    return 0

if __name__ == "__main__":
    exit(main())