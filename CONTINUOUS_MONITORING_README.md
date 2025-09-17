# Continuous Monitoring for SecretSnipe

Real-time file change detection with automatic multi-scanner execution and scheduled reporting.

## 🚀 Features

- **Real-time Monitoring**: Watch directories for file changes using watchdog
- **Multi-Scanner Integration**: Automatically run custom, Trufflehog, and Gitleaks on changes
- **Smart Deduplication**: Avoid duplicate scans using file hashing
- **Critical Alerts**: Immediate webhook notifications for high-severity findings
- **Weekly Reports**: Automated Teams/Slack reports with rich formatting
- **PostgreSQL Backend**: All findings stored with full audit trails
- **Redis Caching**: High-performance caching for monitoring state

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐
│  File Changes   │───▶│ Watchdog Monitor │
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│   Scan Queue    │───▶│ Multi-Scanner   │
│   (Redis)       │    │ Orchestrator    │
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│ PostgreSQL DB   │    │   Webhook       │
│   (Findings)    │    │ Notifications   │
└─────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐
│  Weekly Teams   │
│    Reports      │
└─────────────────┘
```

## 📋 Prerequisites

- PostgreSQL and Redis running
- Teams webhook URL (optional, for reports)
- Directory with read/write permissions
- Python dependencies installed

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Set Teams webhook for weekly reports
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/your-webhook-url"

# Set monitoring directory
export MONITOR_PATH="/path/to/your/codebase"
```

### 2. Start Continuous Monitoring

```bash
# Using Docker Compose
docker-compose --profile monitoring up -d

# Or run directly
python continuous_monitor_pg.py /path/to/monitor --teams-webhook "your-webhook-url"
```

### 3. Verify Operation

```bash
# Check logs
docker-compose logs -f continuous-monitor

# View findings in dashboard
open http://localhost:8050
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `TEAMS_WEBHOOK_URL` | Teams webhook for weekly reports | None | No |
| `MONITOR_PATH` | Directory to monitor | `./scan_data` | No |
| `LOG_LEVEL` | Logging verbosity | INFO | No |

### Teams Webhook Setup

1. **Create Teams Webhook**:
   - Go to your Teams channel
   - Click "⋯" → "Connectors" → "Incoming Webhook"
   - Configure name and image
   - Copy the webhook URL

2. **Set Environment Variable**:
   ```bash
   export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/your-webhook-url"
   ```

## 📊 Weekly Reports

### Report Schedule
- **Frequency**: Every Monday at 9:00 AM
- **Format**: Rich Teams card with interactive elements
- **Content**: 7-day summary with trends and statistics

### Report Contents

```
🔒 Weekly SecretSnipe Security Report
Monitoring: /path/to/directory

📅 Report Period: 2025-01-13 to 2025-01-20

📊 Findings Summary:
• Total Findings: 47
• Critical Issues: 3
• High Severity: 12
• Medium Severity: 32

🔍 Scanner Breakdown:
• Custom Scanner: 15 findings
• Trufflehog: 18 findings
• Gitleaks: 14 findings

[View Dashboard Button]
```

### Customizing Reports

Reports are automatically generated based on:
- Findings from the last 7 days
- All severity levels tracked
- Tool-specific breakdowns
- Project-based filtering

## 🔍 Real-time Alerts

### Trigger Conditions

Alerts are sent immediately when:
- **Critical** severity findings are detected
- **High** severity findings are detected
- New findings match webhook trigger rules

### Alert Format

```json
{
  "event": "secret_found",
  "timestamp": "2025-01-15T14:30:00Z",
  "finding": {
    "id": "uuid-here",
    "file_path": "src/config.py",
    "secret_type": "AWS Access Key",
    "severity": "Critical",
    "tool_source": "trufflehog"
  }
}
```

## 🛠️ Advanced Usage

### Custom Monitoring Paths

```bash
# Monitor specific directory
python continuous_monitor_pg.py /home/user/projects/myapp \
    --project "myapp-monitor" \
    --teams-webhook "https://hooks.slack.com/your-webhook"
```

### Multiple Monitoring Instances

```yaml
# docker-compose.override.yml
services:
  monitor-frontend:
    extends: continuous-monitor
    environment:
      MONITOR_PATH: "/app/frontend"
    command: ["python", "continuous_monitor_pg.py", "/app/frontend", "--project", "frontend"]

  monitor-backend:
    extends: continuous-monitor
    environment:
      MONITOR_PATH: "/app/backend"
    command: ["python", "continuous_monitor_pg.py", "/app/backend", "--project", "backend"]
```

### File Exclusion Rules

The monitor automatically excludes:
- Hidden directories (`.git`, `__pycache__`, etc.)
- Unsupported file types
- Binary files without text content

## 📈 Performance Considerations

### Resource Usage
- **Memory**: ~200MB base + 50MB per active scan
- **CPU**: Minimal when idle, scales with file changes
- **Disk**: Minimal, uses Redis for queue management

### Optimization Tips
- Monitor specific directories instead of entire filesystems
- Use SSD storage for better performance
- Configure appropriate file size limits
- Set up log rotation for long-running instances

## 🔧 Troubleshooting

### Common Issues

**Monitor not detecting changes:**
```bash
# Check permissions
ls -la /path/to/monitor

# Verify watchdog is running
docker-compose logs continuous-monitor
```

**Teams webhook not working:**
```bash
# Test webhook manually
curl -X POST -H "Content-Type: application/json" \
     -d '{"text":"Test"}' \
     $TEAMS_WEBHOOK_URL
```

**Database connection errors:**
```bash
# Check database status
docker-compose ps postgres

# Verify connection
python -c "from database_manager import init_database; init_database()"
```

### Log Analysis

```bash
# View recent activity
docker-compose logs --tail=100 continuous-monitor

# Search for errors
docker-compose logs continuous-monitor | grep ERROR
```

## 🔐 Security Considerations

- **Webhook URLs**: Store securely, use HTTPS
- **File Permissions**: Monitor only necessary directories
- **Network Security**: Use internal networks for database access
- **Secret Handling**: All findings encrypted at rest

## 📝 API Reference

### ContinuousMonitor Class

```python
from continuous_monitor_pg import ContinuousMonitor

# Initialize
monitor = ContinuousMonitor(
    watch_directory=Path("/path/to/watch"),
    project_name="my-project"
)

# Start monitoring
monitor.start()

# Stop monitoring
monitor.stop()
```

### Key Methods

- `queue_file_scan(file_path)`: Manually queue a file for scanning
- `generate_weekly_report()`: Manually trigger report generation
- `check_critical_findings(session_id)`: Check and alert on critical findings

## 🤝 Integration Examples

### CI/CD Integration

```yaml
# .github/workflows/monitor.yml
name: Security Monitoring
on:
  push:
    branches: [main]

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Start Monitoring
        run: |
          docker-compose --profile monitoring up -d
          sleep 30
          docker-compose logs continuous-monitor
```

### Slack Integration

Replace Teams webhook with Slack:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

## 📊 Monitoring Metrics

Track these key metrics:

- **Files Scanned**: Total files processed
- **Findings Detected**: By severity and tool
- **Scan Duration**: Average time per scan
- **Queue Depth**: Pending scans in Redis
- **Error Rate**: Failed scan percentage

## 🚀 Future Enhancements

- **Git Integration**: Monitor specific branches
- **Container Support**: Monitor running containers
- **Advanced Filtering**: Custom inclusion/exclusion rules
- **Multi-tenant**: Separate monitoring per team/project
- **ML-based**: Anomaly detection for unusual patterns