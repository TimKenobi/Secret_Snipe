# SecretSnipe - Internal Wiki Documentation

## Enterprise Secret Detection & Continuous Monitoring Platform

**Version:** 1.0.0  
**Last Updated:** January 2026  
**Maintainer:** IT Security Team  
**GitHub Repository:** https://github.com/TimKenobi/Secret_Snipe

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation & Deployment](#installation--deployment)
5. [Configuration Reference](#configuration-reference)
6. [Dashboard User Guide](#dashboard-user-guide)
7. [Scanning Capabilities](#scanning-capabilities)
8. [Detection Signatures](#detection-signatures)
9. [Jira Integration](#jira-integration)
10. [Multi-Project Management](#multi-project-management)
11. [Continuous Monitoring](#continuous-monitoring)
12. [Webhook & Notifications](#webhook--notifications)
13. [Security Features](#security-features)
14. [Troubleshooting](#troubleshooting)
15. [Performance Tuning](#performance-tuning)
16. [Maintenance & Operations](#maintenance--operations)

---

## Overview

SecretSnipe is a comprehensive secret detection and visualization platform designed for enterprise environments. It provides real-time monitoring of file systems, network shares, and repositories to detect exposed credentials, API keys, and other sensitive information.

### Key Capabilities

- **Multi-Engine Scanning:** Custom regex patterns, TruffleHog, and Gitleaks integration
- **Real-Time Monitoring:** Continuous file system watching with incremental scans
- **Interactive Dashboard:** Web-based visualization with Dash/Plotly
- **Multi-Format Support:** 25+ file types including PDFs, Office documents, images (OCR), and archives
- **Jira Integration:** Automatic ticket creation for security findings
- **Teams Notifications:** Real-time alerts via Microsoft Teams webhooks
- **Enterprise Ready:** PostgreSQL backend, Redis caching, Docker deployment

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                          SecretSnipe Platform                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │  Dashboard  │    │   REST API  │    │   Webhook   │               │
│  │ (Dash/Flask)│    │   (Flask)   │    │   Service   │               │
│  │  Port 8050  │    │             │    │             │               │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘               │
│         │                  │                  │                       │
│         └──────────────────┼──────────────────┘                       │
│                            │                                          │
│              ┌─────────────┴─────────────┐                            │
│              │                           │                            │
│  ┌───────────▼───────────┐   ┌───────────▼───────────┐               │
│  │   PostgreSQL 15       │   │   Redis 7             │               │
│  │   (Findings Storage)  │   │   (Cache/Sessions)    │               │
│  │   Port 5432           │   │   Port 6379           │               │
│  └───────────────────────┘   └───────────────────────┘               │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                    Scanner Services                            │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐    │   │
│  │  │   Custom    │  │  TruffleHog │  │      Gitleaks       │    │   │
│  │  │   Scanner   │  │  (Entropy)  │  │   (Git-Aware)       │    │   │
│  │  │ 25+ Patterns│  │ 800+ Types  │  │   Pattern-Based     │    │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘    │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │               Continuous Monitor (Watchdog)                    │   │
│  │   • Real-time file system events                               │   │
│  │   • Incremental scanning                                       │   │
│  │   • Git diff-based change detection                            │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
CIFS/SMB Mount or Local Directory
         │
         ▼
Scanner Service ─────┬────► Custom Pattern Scanner ─────┐
                     ├────► Gitleaks                    ├──► PostgreSQL
                     └────► TruffleHog ─────────────────┘
                                                              │
                                                              ▼
                     Continuous Monitor ──► Incremental Scans
                                                              │
                     PostgreSQL ◄─────────────────────────────┘
                          │
                          ▼
                     Redis Cache ◄──► Dashboard (Port 8050)
                                          │
                                          ▼
                                  Teams/Jira Notifications
```

### Docker Services

| Service | Container Name | Port | Memory | Purpose |
|---------|---------------|------|--------|---------|
| PostgreSQL | secretsnipe-postgres | 5432 | 1GB | Findings database |
| Redis | secretsnipe-redis | 6379 | 512MB | Caching & sessions |
| Scanner | secretsnipe-scanner | - | 4GB | Secret scanning engine |
| Visualizer | secretsnipe-visualizer | 8050 | 512MB | Web dashboard |
| Continuous Monitor | secretsnipe-continuous | - | 512MB | File system watcher |
| Webhook Service | secretsnipe-webhook | - | 256MB | Notifications API |

---

## Features

### Core Features

| Feature | Description |
|---------|-------------|
| **Multi-Engine Scanning** | Custom patterns, TruffleHog, Gitleaks running in parallel |
| **OCR Support** | Extract text from images (PNG, JPG, BMP, TIFF) using Tesseract/EasyOCR |
| **Archive Scanning** | Recursive extraction and scanning of ZIP files |
| **Office Document Support** | PDF, DOCX, XLSX, PPTX text extraction |
| **Git-Aware Scanning** | Historical commit analysis with verification |
| **Real-Time Monitoring** | Watchdog-based file system event detection |
| **Multi-Project Support** | Manage multiple scan directories with schedules |

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **Dark Mode UI** | Professional dark theme optimized for security operations |
| **Real-Time Updates** | 30-second auto-refresh with live metrics |
| **Severity Filtering** | Filter by Critical/High/Medium/Low |
| **Date Range Filtering** | Historical analysis with date pickers |
| **Export Capabilities** | CSV, JSON, PDF report generation |
| **Interactive Charts** | Findings over time, severity distribution, file type analysis |
| **False Positive Management** | Mark and filter false positives |

### Integration Features

| Feature | Description |
|---------|-------------|
| **Jira Integration** | Auto-create tickets for security findings |
| **Teams Webhooks** | Adaptive cards with severity-based color coding |
| **REST API** | Programmatic access to findings and scans |
| **Weekly Reports** | Automated summary reports every Monday 9 AM |

---

## Installation & Deployment

### Prerequisites

- Docker & Docker Compose v2.0+
- 8GB RAM recommended (4GB minimum)
- Network access to target directories
- (Optional) CIFS/SMB utilities for network share access

### Quick Start

```bash
# Clone repository
git clone https://github.com/TimKenobi/Secret_Snipe.git
cd Secret_Snipe

# Create configuration
cp config.json.example config.json
cp jira_config/jira_config.json.example jira_config/jira_config.json

# Edit configuration files with your settings
nano config.json
nano jira_config/jira_config.json

# Create .env file
cat > .env << EOF
POSTGRES_PASSWORD=your_secure_password
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=YourSecurePassword123!
WEBHOOK_URL=https://your-teams-webhook-url
EOF

# Deploy
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs -f
```

### Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| Dashboard | http://localhost:8050 | From .env file |
| PostgreSQL | localhost:5432 | secretsnipe / from .env |
| Redis | localhost:6379 | No auth (internal only) |

### Network Share (CIFS) Setup

```bash
# Install CIFS utilities
sudo apt-get update && sudo apt-get install -y cifs-utils

# Create credentials file
sudo mkdir -p /etc/samba
sudo tee /etc/samba/credentials > /dev/null <<EOF
username=YOUR_DOMAIN_USERNAME
password=YOUR_PASSWORD
domain=YOUR_DOMAIN
EOF
sudo chmod 600 /etc/samba/credentials

# Create mount point
sudo mkdir -p /mnt/secretsnipe_monitor

# Mount the share
sudo mount -t cifs //server.domain.com/share /mnt/secretsnipe_monitor \
  -o credentials=/etc/samba/credentials,vers=3.0,sec=ntlmssp

# Update .env for Docker
echo "MONITOR_VOLUME=/mnt/secretsnipe_monitor:/monitor:ro" >> .env
```

---

## Configuration Reference

### Environment Variables

#### Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_PASSWORD` | secretsnipe_password | PostgreSQL password |
| `DB_HOST` | postgres | Database host |
| `DB_PORT` | 5432 | Database port |
| `DB_NAME` | secretsnipe | Database name |
| `DB_USER` | secretsnipe | Database user |

#### Scanner Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_TIMEOUT_SECONDS` | 300 | Per-engine timeout (0 = disabled) |
| `MAX_SCAN_DEPTH` | 25 | Maximum directory recursion depth |
| `ENABLE_OCR` | true | Enable image text extraction |
| `OCR_ENGINE` | pytesseract | OCR engine: pytesseract or easyocr |
| `OCR_LANGUAGES` | en | Comma-separated language codes |
| `WORKER_PROCESSES` | 4 | Number of parallel workers |
| `SCANNER_MEMORY_LIMIT_MB` | 512 | Memory limit per worker |
| `MAX_OCR_FILE_SIZE_MB` | 5.0 | Max image file size for OCR |

#### Exclusion Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `EXCLUDED_DIRECTORIES` | node_modules,.git,venv,__pycache__ | Directories to skip |
| `EXCLUDED_EXTENSIONS` | .prn,.bmp,.pdf,.zip,.rar,.7z | File extensions to skip |

#### Dashboard Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DASHBOARD_USERNAME` | admin | Login username |
| `DASHBOARD_PASSWORD` | - | Login password |
| `JWT_SECRET_KEY` | - | JWT signing key (32+ chars) |

#### Notification Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_URL` | - | Microsoft Teams webhook URL |
| `TEAMS_WEBHOOK_URL` | - | Alternative Teams webhook |
| `NOTIFY_ON_CRITICAL` | true | Send alerts for critical findings |
| `NOTIFY_ON_HIGH` | true | Send alerts for high findings |

### config.json Reference

```json
{
  "debug": false,
  "log_level": "INFO",
  "database": {
    "host": "localhost",
    "port": 5432,
    "database": "secretsnipe",
    "username": "secretsnipe",
    "password": "your_password",
    "connection_pool_size": 10
  },
  "redis": {
    "host": "localhost",
    "port": 6379,
    "max_connections": 20
  },
  "scanner": {
    "threads": 4,
    "timeout_seconds": 300,
    "max_file_size_mb": 100,
    "memory_limit_mb": 512,
    "enable_ocr": true
  },
  "webhook": {
    "enabled": true,
    "url": "https://your-webhook-endpoint",
    "headers": {
      "Authorization": "Bearer your-token"
    }
  },
  "dashboard": {
    "host": "0.0.0.0",
    "port": 8050,
    "enable_auth": true,
    "rate_limit_requests": 100,
    "session_timeout_minutes": 30
  }
}
```

---

## Dashboard User Guide

### Accessing the Dashboard

1. Navigate to `http://your-server:8050`
2. Login with configured credentials
3. Dashboard auto-refreshes every 30 seconds

### Main Dashboard Components

#### Summary Statistics Panel
- **Total Findings:** All detected secrets
- **Critical/High/Medium/Low:** Severity breakdown
- **Files Scanned:** Total files processed
- **Last Scan:** Timestamp of most recent scan

#### Findings Over Time Chart
- Time-series visualization of discoveries
- Filterable by date range
- Shows trend analysis

#### Severity Distribution Pie Chart
- Visual breakdown by severity level
- Click to filter table

#### Scanner Performance Chart
- Comparison of findings by tool
- Custom vs TruffleHog vs Gitleaks

#### Findings Table
- Sortable columns
- Click row for details
- Export selection to CSV/JSON
- Mark as false positive

### Filtering Options

| Filter | Description |
|--------|-------------|
| Date Range | Select start/end dates |
| Severity | Critical, High, Medium, Low |
| Scanner Tool | Custom, TruffleHog, Gitleaks |
| File Type | Filter by extension |
| Project | Multi-project filter |
| Search | Full-text search |

### Export Features

1. Click **Export** button
2. Select format: CSV, JSON, or PDF
3. Choose filters to apply
4. Download generated report

---

## Scanning Capabilities

### Supported File Types

#### Source Code
`.py`, `.js`, `.ts`, `.java`, `.cpp`, `.c`, `.h`, `.php`, `.rb`, `.go`, `.rs`, `.swift`, `.kt`, `.scala`

#### Configuration Files
`.json`, `.xml`, `.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`, `.conf`, `.properties`, `.env`

#### Documents
`.pdf`, `.docx`, `.xlsx`, `.pptx`, `.doc`, `.xls`, `.ppt`, `.txt`, `.md`

#### Images (with OCR)
`.jpg`, `.jpeg`, `.png`, `.bmp`, `.tiff`, `.gif`, `.webp`

#### Archives (recursive extraction)
`.zip`, `.tar`, `.gz`, `.bz2`

### Scanner Engines

#### Custom Pattern Scanner
- 25+ built-in regex patterns
- Configurable via `signatures.json`
- Low false-positive rate
- Fast execution

#### TruffleHog
- 800+ secret type classification
- Entropy-based detection
- Credential verification (checks if secrets are live)
- Git history analysis
- Deep analysis for common credential types

#### Gitleaks
- Git-aware scanning
- Pattern-based detection
- Support for custom rules
- Pre-commit hook integration

### Scan Types

| Type | Description | Use Case |
|------|-------------|----------|
| `full` | All scanners, all files | Initial scan, periodic full scan |
| `incremental` | Changed files only | Continuous monitoring |
| `custom_only` | Custom patterns only | Quick validation |
| `trufflehog_only` | TruffleHog only | Deep credential analysis |
| `gitleaks_only` | Gitleaks only | Git repository scanning |

---

## Detection Signatures

### Critical Severity

| Pattern | Description |
|---------|-------------|
| Private Key | RSA, EC, OPENSSH, PGP private keys |
| Database Connection String | JDBC, MySQL, PostgreSQL, MongoDB URIs |
| AWS Secret Access Key | AWS IAM secret keys |
| GitHub Token | ghp_, gho_, ghu_, ghs_, ghr_ tokens |
| GitLab Token | glpat- tokens |
| Stripe API Key | sk_live_, pk_live_ keys |
| OpenAI API Key | sk- followed by 48 chars |
| Credit Card Number | Visa, Mastercard, Amex, Discover |
| Email with Password | Credential pairs in same context |
| Azure Storage Key | 86-char base64 storage keys |

### High Severity

| Pattern | Description |
|---------|-------------|
| Hardcoded Password | password=, secret=, token= patterns |
| API Key | Generic api_key patterns |
| AWS Access Key ID | AKIA prefix keys |
| JWT Token | eyJ... structure tokens |
| Bearer Token | HTTP authorization tokens |
| Slack Token | xox tokens |
| Slack Webhook | hooks.slack.com URLs |
| Google API Key | AIza prefix keys |
| SendGrid API Key | SG. prefix keys |
| Twilio API Key | SK prefix keys |
| NPM Token | npm_ prefix tokens |
| Social Security Number | SSN with context |

### Medium Severity

| Pattern | Description |
|---------|-------------|
| Private IP Address | 10.x.x.x, 172.16-31.x.x, 192.168.x.x |
| SSN Format | XXX-XX-XXXX (requires verification) |

### Low Severity

| Pattern | Description |
|---------|-------------|
| Confidentiality Marker | "Confidential", "Internal Use Only", etc. |

### Custom Signatures

Edit `signatures.json` to add custom patterns:

```json
{
  "name": "Internal API Key",
  "regex": "INTERNAL_API_[A-Za-z0-9]{32}",
  "severity": "High",
  "description": "Internal application API key"
}
```

---

## Jira Integration

### Configuration

Edit `jira_config/jira_config.json`:

```json
{
  "server_url": "https://your-company.atlassian.net",
  "username": "your-email@company.com",
  "api_token": "YOUR_JIRA_API_TOKEN",
  "project_key": "SEC",
  "issue_type": "Task",
  "labels": ["secretsnipe", "security", "secret-detection"]
}
```

### Creating API Token

1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Click **Create API token**
3. Name it "SecretSnipe" and copy the token
4. Paste into `jira_config.json`

### Features

- **Automatic Ticket Creation:** Create tickets from dashboard
- **Batch Operations:** Create tickets for multiple findings
- **File-Based Grouping:** Group findings by file path
- **Rich Descriptions:** Include secret type, location, context
- **Custom Fields Support:** Map to your Jira custom fields
- **Duplicate Prevention:** Check for existing tickets

### Creating Tickets from Dashboard

1. Select findings in the table
2. Click **Create Jira Ticket** button
3. Choose grouping option:
   - Individual tickets per finding
   - Grouped by file
   - Single ticket for all
4. Confirm creation

---

## Multi-Project Management

### Overview

Manage multiple scan directories/projects from the dashboard with independent schedules and configurations.

### Adding a Project

1. Click **📂 Projects** button in header
2. Click **Add Directory**
3. Fill in:
   - **Path:** Absolute path to directory
   - **Display Name:** Friendly name
   - **Schedule:** Manual, Hourly, Daily, Weekly
   - **Priority:** 1-10 (higher = scanned first)
4. Click **Save**

### Project Settings

| Setting | Description |
|---------|-------------|
| `directory_path` | Absolute path to scan |
| `display_name` | Friendly name for UI |
| `schedule` | manual, hourly, daily, weekly |
| `priority` | 1-10 scan priority |
| `include_patterns` | Glob patterns to include |
| `exclude_patterns` | Glob patterns to exclude |
| `is_active` | Enable/disable scanning |

### Triggering Scans

1. Click **📂 Projects** button
2. Find project in list
3. Click **⚡ Trigger Scan**
4. Select scan type:
   - Full Scan
   - Incremental
   - Custom Only
   - TruffleHog Only
   - Gitleaks Only
5. Confirm

### Database Tables

```sql
-- Projects table
CREATE TABLE scan_directories (
    id SERIAL PRIMARY KEY,
    directory_path TEXT UNIQUE NOT NULL,
    display_name TEXT,
    schedule VARCHAR(50) DEFAULT 'manual',
    priority INTEGER DEFAULT 5,
    include_patterns TEXT[],
    exclude_patterns TEXT[],
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    last_scan_at TIMESTAMP
);

-- Scan queue
CREATE TABLE scan_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id INTEGER REFERENCES scan_directories(id),
    scan_type VARCHAR(50) DEFAULT 'full',
    status VARCHAR(20) DEFAULT 'pending',
    priority INTEGER DEFAULT 5,
    files_scanned INTEGER,
    findings_count INTEGER,
    error_message TEXT,
    requested_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);
```

---

## Continuous Monitoring

### Overview

The continuous monitor watches file systems for changes and triggers incremental scans automatically.

### Configuration

```bash
# Environment variables
ENABLE_CONTINUOUS_MONITORING=true
SCAN_INTERVAL_HOURS=24
MONITOR_VOLUME=/path/to/watch:/monitor:ro
```

### How It Works

1. **Watchdog Service:** Monitors file system events
2. **Event Detection:** Creates, modifies, deletes, moves
3. **Debouncing:** Prevents duplicate scans (cooldown period)
4. **Incremental Scan:** Only processes changed files
5. **Results Storage:** New findings added to database
6. **Notifications:** Alerts sent for critical findings

### Starting the Monitor

```bash
# Using Docker Compose
docker-compose --profile monitoring up -d continuous-monitor

# Standalone
python continuous_monitor_pg.py /path/to/watch
```

### Weekly Reports

Automatic summary sent every Monday at 9:00 AM via Teams webhook:

- 📊 Total findings for the week
- 🚨 Critical/High severity counts
- 🔍 Scanner-specific statistics
- 📈 Trend analysis
- 📁 Most affected files

---

## Webhook & Notifications

### Microsoft Teams Integration

#### Setup

1. In Teams, go to channel → Connectors
2. Add **Incoming Webhook**
3. Name it "SecretSnipe Alerts"
4. Copy the webhook URL
5. Add to `.env`:

```bash
WEBHOOK_URL=https://company.webhook.office.com/webhookb2/...
TEAMS_WEBHOOK_URL=https://company.webhook.office.com/webhookb2/...
```

#### Notification Format

Teams cards include:
- 🔴 Severity-based color coding
- 📁 File path and line number
- 🔍 Secret type and description
- 🛠️ Scanner tool that found it
- ⏰ Discovery timestamp
- 🔗 Link to dashboard

#### Notification Thresholds

```bash
NOTIFY_ON_CRITICAL=true   # Always notify
NOTIFY_ON_HIGH=true       # Notify by default
NOTIFY_ON_MEDIUM=false    # Optional
NOTIFY_ON_LOW=false       # Usually disabled
```

### Generic Webhook Configuration

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
      "Content-Type": "application/json",
      "Authorization": "Bearer your-token"
    }
  }
}
```

### Webhook Payload Format

```json
{
  "event": "secret_detected",
  "timestamp": "2026-01-15T10:30:00Z",
  "finding": {
    "id": "uuid",
    "secret_type": "AWS Access Key",
    "severity": "Critical",
    "file_path": "/path/to/file.py",
    "line_number": 42,
    "tool": "trufflehog",
    "masked_secret": "AKIA***********XYZ",
    "verified": true
  },
  "project": "my-project"
}
```

---

## Security Features

### Authentication & Authorization

| Feature | Description |
|---------|-------------|
| Session-Based Auth | Flask sessions with secure cookies |
| bcrypt Password Hashing | Industry-standard password storage |
| JWT Tokens | Optional API authentication |
| Session Timeout | Automatic logout after inactivity |
| Login Attempt Monitoring | Track failed login attempts |

### Rate Limiting

```python
# Default configuration
RATE_LIMIT_REQUESTS = 100      # requests per window
RATE_LIMIT_WINDOW = 60         # seconds
```

- IP-based request throttling
- Configurable per-endpoint limits
- Automatic blocked IP tracking
- Redis-backed for distributed deployments

### Input Validation

| Protection | Description |
|------------|-------------|
| SQL Injection | Parameterized queries |
| XSS Prevention | Output encoding |
| CSRF Protection | Token validation |
| Input Sanitization | Length limits, character filtering |
| Path Traversal | Normalized path validation |

### Audit Logging

All actions are logged:
- User logins/logouts
- Scan operations
- Finding access
- Export operations
- Configuration changes
- Failed authentication

Log location: `dashboard_audit.log`

### Secret Masking

Detected secrets are automatically masked in:
- Dashboard display
- Exported reports
- Log files
- API responses
- Webhook notifications

Example: `AKIAIOSFODNN7EXAMPLE` → `AKIA***********MPLE`

### Network Security

| Feature | Description |
|---------|-------------|
| Docker Network Isolation | Services on internal network |
| TLS Support | Optional HTTPS for dashboard |
| Allowed IPs | Whitelist configuration |
| Blocked IPs | Automatic blocking |

---

## Troubleshooting

### Common Issues

#### Scanner Crashes (Exit Code 137)

**Symptom:** Container exits with code 137 (OOM killed)

**Solutions:**
1. Increase memory limit:
   ```bash
   SCANNER_MEMORY_LIMIT_MB=2048
   ```
2. Reduce worker processes:
   ```bash
   WORKER_PROCESSES=2
   ```
3. Add more file exclusions:
   ```bash
   EXCLUDED_EXTENSIONS=.pdf,.zip,.rar,.7z,.bmp,.tiff
   ```

#### No Files Found

**Symptom:** Scanner reports 0 files processed

**Solutions:**
1. Check CIFS mount:
   ```bash
   mount | grep secretsnipe
   ```
2. Verify permissions:
   ```bash
   docker exec secretsnipe-scanner ls -la /monitor
   ```
3. Check path in configuration

#### Dashboard Access Issues

**Symptom:** Connection refused or blank page

**Solutions:**
1. Check container status:
   ```bash
   docker-compose ps
   docker logs secretsnipe-visualizer
   ```
2. Verify port mapping:
   ```bash
   netstat -tlnp | grep 8050
   ```
3. Check firewall rules

#### Database Connection Errors

**Symptom:** "Connection refused" or timeout errors

**Solutions:**
1. Check PostgreSQL status:
   ```bash
   docker logs secretsnipe-postgres
   ```
2. Test connectivity:
   ```bash
   docker exec secretsnipe-postgres psql -U secretsnipe -d secretsnipe -c "SELECT 1;"
   ```
3. Verify credentials in .env

#### Authentication Problems

**Symptom:** Cannot login to dashboard

**Solutions:**
1. Verify credentials:
   ```bash
   grep DASHBOARD .env
   ```
2. Clear browser cookies
3. Check audit log for errors

### Debug Commands

```bash
# Container status
docker-compose ps
docker stats

# Service logs
docker logs secretsnipe-scanner --tail 100
docker logs secretsnipe-visualizer --tail 100
docker logs secretsnipe-postgres --tail 50

# Environment check
docker exec secretsnipe-scanner env | grep -E "(DB_|REDIS_|EXCLUDED)"

# Database connectivity
docker exec secretsnipe-scanner python3 -c "from database_manager import db_manager; print(db_manager.test_connection())"

# Redis connectivity
docker exec secretsnipe-redis redis-cli ping

# CIFS mount check
docker exec secretsnipe-scanner mount | grep cifs
docker exec secretsnipe-scanner ls -la /monitor
```

---

## Performance Tuning

### Scanner Optimization

```json
{
  "scanner": {
    "threads": 8,                    // Increase for more parallelism
    "timeout_seconds": 600,          // Increase for large files
    "max_file_size_mb": 50,         // Reduce to skip large files
    "memory_limit_mb": 1024,         // Increase if RAM available
    "trufflehog_concurrency": 4,     // TruffleHog workers
    "gitleaks_max_depth": 10         // Git history depth
  }
}
```

### Database Optimization

```sql
-- Create indexes for common queries
CREATE INDEX CONCURRENTLY idx_findings_severity 
ON findings(severity);

CREATE INDEX CONCURRENTLY idx_findings_project_date 
ON findings(project_id, first_seen DESC);

CREATE INDEX CONCURRENTLY idx_findings_composite 
ON findings(project_id, scan_session_id, severity, first_seen DESC);

-- Analyze tables for query planner
ANALYZE findings;
```

### Redis Configuration

```
maxmemory 1gb
maxmemory-policy volatile-lru
appendonly yes
appendfsync everysec
```

### Memory Optimization

| Setting | Recommended | Description |
|---------|-------------|-------------|
| `WORKER_PROCESSES` | 2-4 | Parallel workers |
| `OCR_ENGINE` | pytesseract | Lower memory than EasyOCR |
| `MAX_OCR_FILE_SIZE_MB` | 3.0 | Limit large image processing |
| `OCR_RESET_AFTER_IMAGES` | 50 | Reset OCR memory periodically |

### File Exclusion Strategy

Exclude large binary files that rarely contain secrets:

```bash
EXCLUDED_EXTENSIONS=.pdf,.zip,.rar,.7z,.prn,.bmp,.tiff,.tif,.mov,.mp4,.avi,.wmv,.flv,.mkv
EXCLUDED_DIRECTORIES=node_modules,.git,venv,__pycache__,~snapshot,Measurements
```

---

## Maintenance & Operations

### Backup Procedures

#### Database Backup

```bash
# Manual backup
docker exec secretsnipe-postgres pg_dump -U secretsnipe secretsnipe > backup_$(date +%Y%m%d).sql

# Automated backup script
./scripts/backup_postgres.sh
```

#### Configuration Backup

```bash
# Backup configuration files
tar -czf config_backup_$(date +%Y%m%d).tar.gz \
  config.json \
  jira_config/jira_config.json \
  .env \
  signatures.json
```

### Database Restore

```bash
# Stop services
docker-compose down

# Start only database
docker-compose up -d postgres

# Restore backup
cat backup_20260115.sql | docker exec -i secretsnipe-postgres psql -U secretsnipe -d secretsnipe

# Start all services
docker-compose up -d
```

### Log Rotation

Logs are automatically rotated:
- Maximum size: 100MB per file
- Retention: 3 files
- Location: `./logs/`

### Health Monitoring

```bash
# Check all services
docker-compose ps

# Database health
docker exec secretsnipe-postgres pg_isready -U secretsnipe

# Redis health
docker exec secretsnipe-redis redis-cli ping

# API health endpoint
curl http://localhost:8050/health
```

### Updating SecretSnipe

```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose build --no-cache

# Restart services
docker-compose down
docker-compose up -d

# Verify
docker-compose ps
docker logs secretsnipe-visualizer --tail 20
```

### Resource Monitoring

```bash
# Real-time container stats
docker stats

# Disk usage
docker system df

# Clean unused resources
docker system prune -f
```

---

## Support & Resources

### Documentation

- [README.md](./README.md) - Quick start guide
- [PRODUCTION_SETUP_GUIDE.md](./PRODUCTION_SETUP_GUIDE.md) - Production deployment
- [docs/](./docs/) - Complete documentation directory
- [MEMORY_OPTIMIZATION.md](./MEMORY_OPTIMIZATION.md) - Memory tuning guide

### External Resources

- **TruffleHog Documentation:** https://github.com/trufflesecurity/trufflehog
- **Gitleaks Documentation:** https://github.com/gitleaks/gitleaks
- **PostgreSQL Documentation:** https://www.postgresql.org/docs/
- **Redis Documentation:** https://redis.io/docs/

### Contact

- **GitHub Issues:** https://github.com/TimKenobi/Secret_Snipe/issues
- **IT Security Team:** [Internal contact]

---

*SecretSnipe - Keeping your secrets safe through continuous monitoring and detection*

**Document Version:** 1.0.0  
**Last Updated:** January 15, 2026
