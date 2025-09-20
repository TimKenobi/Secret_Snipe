# Webhook Integration Guide

SecretSnipe supports webhook integration for real-time notifications about security findings and scan events.

## 🎯 Overview

Webhooks allow you to receive instant notifications when:
- New security findings are detected
- Scans are completed or fail
- Critical security events occur
- Weekly summary reports are generated

## ⚙️ Configuration

### Basic Setup

Configure webhooks in your `config.json`:

```json
{
  "webhook": {
    "enabled": true,
    "url": "https://your-endpoint.com/webhook",
    "method": "POST",
    "timeout_seconds": 30,
    "retry_attempts": 3,
    "retry_delay_seconds": 5,
    "headers": {
      "Authorization": "Bearer your-token",
      "Content-Type": "application/json"
    }
  }
}
```

### Environment Variables

You can also configure webhooks using environment variables:

```bash
# Basic webhook configuration
WEBHOOK_URL=https://your-endpoint.com/webhook
WEBHOOK_METHOD=POST
WEBHOOK_TIMEOUT=30

# Authentication
WEBHOOK_AUTH_TOKEN=your-secret-token
WEBHOOK_AUTH_TYPE=Bearer  # or 'Basic'

# Retry configuration
WEBHOOK_RETRY_ATTEMPTS=3
WEBHOOK_RETRY_DELAY=5

# Custom headers
WEBHOOK_HEADER_X_API_KEY=your-api-key
```

### Microsoft Teams Integration

For Microsoft Teams notifications:

```bash
# Teams webhook URL (from Teams channel connectors)
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/your-webhook-id

# Optional: Custom message format
TEAMS_MESSAGE_TEMPLATE="🚨 SecretSnipe Alert: {finding_count} new findings in {project_name}"
```

## 📋 Event Types

### New Finding Event

Triggered when a new security finding is detected.

```json
{
  "event": "new_finding",
  "timestamp": "2025-01-15T10:30:00Z",
  "webhook_id": "wh-12345",
  "finding": {
    "id": "finding-uuid",
    "project_id": "project-uuid",
    "project_name": "my-project",
    "scan_session_id": "scan-uuid",
    "file_path": "/path/to/secret/file.py",
    "line_number": 25,
    "secret_type": "AWS API Key",
    "severity": "high",
    "confidence": 0.95,
    "context": "aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'",
    "masked_secret": "AKIAIOSFODNN7*****",
    "tags": ["aws", "api-key", "production"],
    "first_seen": "2025-01-15T10:30:00Z"
  },
  "scan": {
    "id": "scan-uuid",
    "start_time": "2025-01-15T10:00:00Z",
    "files_scanned": 15420,
    "findings_count": 1250
  }
}
```

### Scan Completed Event

Triggered when a scan session finishes successfully.

```json
{
  "event": "scan_completed",
  "timestamp": "2025-01-15T11:30:00Z",
  "webhook_id": "wh-12345",
  "scan": {
    "id": "scan-uuid",
    "project_id": "project-uuid",
    "project_name": "my-project",
    "status": "completed",
    "start_time": "2025-01-15T10:00:00Z",
    "end_time": "2025-01-15T11:30:00Z",
    "duration_seconds": 5400,
    "files_scanned": 15420,
    "findings_count": 1250,
    "errors_count": 5,
    "scanner_version": "2.1.0"
  },
  "summary": {
    "findings_by_severity": {
      "critical": 15,
      "high": 45,
      "medium": 120,
      "low": 1070
    },
    "top_secret_types": [
      {"type": "AWS API Key", "count": 234},
      {"type": "GitHub Token", "count": 189},
      {"type": "Database Password", "count": 156}
    ]
  }
}
```

### Scan Failed Event

Triggered when a scan session fails.

```json
{
  "event": "scan_failed",
  "timestamp": "2025-01-15T11:30:00Z",
  "webhook_id": "wh-12345",
  "scan": {
    "id": "scan-uuid",
    "project_id": "project-uuid",
    "project_name": "my-project",
    "status": "failed",
    "start_time": "2025-01-15T10:00:00Z",
    "end_time": "2025-01-15T11:30:00Z",
    "duration_seconds": 5400,
    "files_scanned": 8500,
    "findings_count": 750,
    "errors_count": 25,
    "error_message": "Connection timeout to scan target",
    "scanner_version": "2.1.0"
  }
}
```

### Weekly Summary Event

Triggered every Monday at 9:00 AM with weekly statistics.

```json
{
  "event": "weekly_summary",
  "timestamp": "2025-01-20T09:00:00Z",
  "webhook_id": "wh-12345",
  "period": {
    "start_date": "2025-01-13",
    "end_date": "2025-01-19"
  },
  "summary": {
    "total_scans": 42,
    "total_findings": 8750,
    "new_findings": 1250,
    "resolved_findings": 980,
    "findings_by_severity": {
      "critical": 45,
      "high": 234,
      "medium": 1234,
      "low": 7237
    },
    "findings_by_status": {
      "new": 1250,
      "acknowledged": 2500,
      "resolved": 4000,
      "false_positive": 1000
    },
    "top_projects": [
      {"name": "web-app", "findings": 3200},
      {"name": "api-server", "findings": 2800},
      {"name": "mobile-app", "findings": 1800}
    ],
    "trends": {
      "findings_change_percent": 12.5,
      "resolution_rate_percent": 78.4
    }
  }
}
```

## 🔒 Security

### HMAC Signature Validation

SecretSnipe can sign webhook payloads using HMAC-SHA256:

```python
import hmac
import hashlib
import json

def verify_webhook_signature(payload, signature, secret):
    expected_signature = hmac.new(
        secret.encode(),
        json.dumps(payload, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)
```

Configure HMAC signing:

```json
{
  "webhook": {
    "hmac_secret": "your-webhook-secret",
    "hmac_header": "X-Signature"
  }
}
```

### Request Headers

All webhook requests include these headers:

```
User-Agent: SecretSnipe-Webhook/2.1.0
Content-Type: application/json
X-Webhook-ID: wh-12345
X-Webhook-Event: new_finding
X-Webhook-Timestamp: 2025-01-15T10:30:00Z
X-Signature: sha256=abc123... (if HMAC enabled)
```

## 🛠️ Implementation Examples

### Python Webhook Receiver

```python
from flask import Flask, request, jsonify
import json
import hmac
import hashlib

app = Flask(__name__)
WEBHOOK_SECRET = "your-webhook-secret"

def verify_signature(payload, signature):
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        json.dumps(payload, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    payload = request.get_json()
    signature = request.headers.get('X-Signature')

    if signature and not verify_signature(payload, signature):
        return jsonify({'error': 'Invalid signature'}), 401

    event_type = payload.get('event')

    if event_type == 'new_finding':
        handle_new_finding(payload['finding'])
    elif event_type == 'scan_completed':
        handle_scan_completed(payload['scan'])
    elif event_type == 'weekly_summary':
        handle_weekly_summary(payload['summary'])

    return jsonify({'status': 'received'}), 200

def handle_new_finding(finding):
    print(f"New finding: {finding['secret_type']} in {finding['file_path']}")
    # Send alert to security team
    # Update ticketing system
    # Trigger remediation workflow

def handle_scan_completed(scan):
    print(f"Scan completed: {scan['findings_count']} findings")
    # Update dashboard
    # Send notifications
    # Generate reports

def handle_weekly_summary(summary):
    print(f"Weekly summary: {summary['total_findings']} total findings")
    # Send weekly report to management
    # Update compliance dashboard

if __name__ == '__main__':
    app.run(port=5000)
```

### Node.js Webhook Receiver

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const WEBHOOK_SECRET = 'your-webhook-secret';

function verifySignature(payload, signature) {
    const expectedSignature = crypto
        .createHmac('sha256', WEBHOOK_SECRET)
        .update(JSON.stringify(payload, Object.keys(payload).sort()))
        .digest('hex');

    return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
    );
}

app.post('/webhook', (req, res) => {
    const payload = req.body;
    const signature = req.headers['x-signature'];

    if (signature && !verifySignature(payload, signature)) {
        return res.status(401).json({ error: 'Invalid signature' });
    }

    const eventType = payload.event;

    switch (eventType) {
        case 'new_finding':
            handleNewFinding(payload.finding);
            break;
        case 'scan_completed':
            handleScanCompleted(payload.scan);
            break;
        case 'weekly_summary':
            handleWeeklySummary(payload.summary);
            break;
    }

    res.json({ status: 'received' });
});

function handleNewFinding(finding) {
    console.log(`New finding: ${finding.secret_type} in ${finding.file_path}`);
    // Send alert to security team
    // Update ticketing system
    // Trigger remediation workflow
}

function handleScanCompleted(scan) {
    console.log(`Scan completed: ${scan.findings_count} findings`);
    // Update dashboard
    // Send notifications
    // Generate reports
}

function handleWeeklySummary(summary) {
    console.log(`Weekly summary: ${summary.total_findings} total findings`);
    // Send weekly report to management
    // Update compliance dashboard
}

app.listen(5000, () => {
    console.log('Webhook receiver listening on port 5000');
});
```

### Microsoft Teams Integration

```python
import requests
import json

def send_teams_message(webhook_url, finding):
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "0076D7",
        "summary": f"🚨 SecretSnipe Alert: {finding['secret_type']}",
        "sections": [{
            "activityTitle": f"🚨 New {finding['secret_type']} Detected",
            "activitySubtitle": f"Project: {finding['project_name']}",
            "activityImage": "https://example.com/security-icon.png",
            "facts": [
                {
                    "name": "File:",
                    "value": finding['file_path']
                },
                {
                    "name": "Line:",
                    "value": str(finding['line_number'])
                },
                {
                    "name": "Severity:",
                    "value": finding['severity'].upper()
                },
                {
                    "name": "Secret Type:",
                    "value": finding['secret_type']
                }
            ],
            "text": f"**Context:** {finding['context']}"
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name": "View in Dashboard",
            "targets": [{
                "os": "default",
                "uri": f"http://localhost:8050/project/{finding['project_id']}"
            }]
        }]
    }

    response = requests.post(
        webhook_url,
        json=card,
        headers={'Content-Type': 'application/json'}
    )

    return response.status_code == 200
```

## 🔧 Troubleshooting

### Common Issues

1. **Webhook Not Receiving Events**
   - Check if webhook URL is accessible
   - Verify firewall rules allow outbound connections
   - Check webhook timeout settings

2. **Invalid Signature Errors**
   - Ensure HMAC secret is correctly configured
   - Check that payload is parsed correctly before signature verification
   - Verify signature header format

3. **Timeout Errors**
   - Increase webhook timeout in configuration
   - Check network connectivity to webhook endpoint
   - Implement asynchronous processing for slow endpoints

4. **Rate Limiting**
   - Implement queuing for high-volume scenarios
   - Use webhook batching for multiple events
   - Consider webhook filtering to reduce noise

### Debugging

Enable webhook debugging in logs:

```json
{
  "logging": {
    "webhook_debug": true,
    "webhook_payload_log": true
  }
}
```

Check webhook delivery status:

```bash
# View webhook logs
docker-compose logs | grep webhook

# Check webhook configuration
curl http://localhost:8050/api/v1/webhook/status
```

## 📊 Best Practices

1. **Use HTTPS**: Always use HTTPS for webhook endpoints
2. **Validate Signatures**: Implement HMAC signature validation
3. **Handle Failures**: Implement retry logic and failure handling
4. **Rate Limiting**: Implement rate limiting on your webhook endpoint
5. **Idempotency**: Make webhook processing idempotent
6. **Monitoring**: Monitor webhook delivery success rates
7. **Filtering**: Use event filtering to reduce noise
8. **Batching**: Consider batching multiple events for efficiency

## 🔄 Event Filtering

Filter webhook events to reduce noise:

```json
{
  "webhook": {
    "events": ["new_finding", "scan_completed"],
    "filters": {
      "severity": ["critical", "high"],
      "secret_types": ["AWS API Key", "Database Password"],
      "projects": ["production-app", "critical-infra"]
    }
  }
}
```

---

*Last updated: September 19, 2025*