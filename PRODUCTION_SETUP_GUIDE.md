# SecretSnipe Dashboard - Complete Setup & Configuration Guide

## 🎯 Overview

SecretSnipe is a comprehensive secret scanning and monitoring solution designed for enterprise environments. It provides real-time monitoring of file systems, network shares, and repositories to detect exposed credentials, API keys, and other sensitive information.

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB+ RAM recommended
- Network access to target monitoring directories
- (Optional) CIFS/SMB network share access

### 1. Clone and Setup
```bash
git clone https://github.com/TimKenobi/Secret_Snipe.git
cd Secret_Snipe
cp env_example .env
```

### 2. Configure Environment
Edit `.env` file with your settings:
```bash
# Required: Database password
POSTGRES_PASSWORD=your_secure_password

# Required: Dashboard credentials
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=YourSecurePassword123!

# Optional: Teams notifications
WEBHOOK_URL=https://your-teams-webhook-url
```

### 3. Deploy
```bash
docker-compose up -d
```

### 4. Access Dashboard
- URL: http://localhost:8050
- Login with credentials from `.env`

## 📋 Detailed Configuration

### Authentication & Security

The dashboard includes robust authentication and security features:

#### Login Configuration
```env
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=YourSecurePassword123!
JWT_SECRET_KEY=your_jwt_secret_minimum_32_chars
```

#### Security Features
- ✅ Session-based authentication with bcrypt password hashing
- ✅ Rate limiting (100 requests per 60 seconds per IP)
- ✅ CSRF protection
- ✅ Input sanitization and validation
- ✅ Audit logging
- ✅ SQL injection prevention

### Database Configuration

PostgreSQL database with automatic schema initialization:

```env
POSTGRES_PASSWORD=secure_password
POSTGRES_DB=secretsnipe
POSTGRES_USER=secretsnipe
```

**Database Features:**
- Automatic table creation and migration
- Connection pooling
- Query optimization
- Backup-ready schema

### Monitoring Configuration

#### File System Monitoring
```env
ENABLE_CONTINUOUS_MONITORING=true
SCAN_INTERVAL_HOURS=24
MAX_FILE_SIZE_MB=100
```

#### Network Share Monitoring (CIFS)
```env
# Production CIFS configuration
MONITOR_VOLUME=//server.domain.com/share:/monitor:ro,uid=1000,gid=1000
CIFS_USERNAME=domain_user
CIFS_PASSWORD=secure_password
CIFS_DOMAIN=company.com
```

### Notification Configuration

#### Teams Integration
```env
WEBHOOK_URL=https://company.webhook.office.com/webhookb2/...
TEAMS_WEBHOOK_URL=https://company.webhook.office.com/webhookb2/...

# Notification thresholds
NOTIFY_ON_CRITICAL=true
NOTIFY_ON_HIGH=true
NOTIFY_ON_MEDIUM=false
NOTIFY_ON_LOW=false
```

**Teams Card Features:**
- 🎨 Adaptive card formatting
- 🔴 Severity-based color coding
- 📁 File path and detection details
- 🛠️ Scanner tool identification
- ⏰ Timestamp information

## 🔧 Advanced Features

### Scanning Capabilities

**Supported Scanners:**
- **GitLeaks**: Git repository secret detection
- **TruffleHog**: Historical and entropy-based scanning
- **Custom Patterns**: Configurable regex patterns

**File Type Support:**
- Source code files (.py, .js, .ts, .java, .cpp, .c, .php, .rb, .go, .rs)
- Configuration files (.json, .xml, .yaml, .yml, .ini, .conf)
- Documentation (.md, .txt, .rst)
- Database files (.sql)

### Dashboard Features

#### 📊 Analytics & Visualizations
- **Findings Over Time**: Trend analysis with time-series charts
- **Severity Distribution**: Pie chart breakdown by severity levels
- **Tool Source Analysis**: Scanner performance comparison
- **File Extension Analysis**: File type distribution with discrete colors
- **Summary Statistics**: Real-time metrics and counts

#### 📋 Data Management
- **Enhanced Table Views**: Sortable, filterable data tables
- **Custom Report Export**: CSV, JSON, and PDF formats with metadata
- **Date Range Filtering**: Historical data analysis
- **Severity Filtering**: Focus on critical findings

#### 🎨 User Interface
- **Permanent Dark Mode**: Professional dark theme optimized for security operations
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **1080p Optimized**: Viewport-relative sizing for optimal screen utilization
- **Accessibility**: Proper contrast ratios and keyboard navigation

### Security Architecture

#### Authentication System
```python
# Flask-based server-side authentication
- bcrypt password hashing
- Session management with secure cookies
- Automatic session timeout
- Login attempt monitoring
```

#### Rate Limiting & Protection
```python
# Redis-based rate limiting
- IP-based request throttling
- Configurable limits per endpoint
- Automatic blocked IP tracking
- Security event logging
```

#### Audit & Compliance
```python
# Comprehensive audit logging
- User action tracking
- Security event monitoring
- Access pattern analysis
- Compliance reporting
```

## 🚀 Production Deployment

### Docker Swarm Deployment
```yaml
version: '3.8'
services:
  visualizer:
    image: secret_snipe-visualizer
    deploy:
      replicas: 2
      restart_policy:
        condition: on-failure
    networks:
      - secretsnipe-network
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secretsnipe-dashboard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secretsnipe
  template:
    spec:
      containers:
      - name: dashboard
        image: secret_snipe-visualizer:latest
        ports:
        - containerPort: 8050
```

### Production Checklist

#### Security Hardening
- [ ] Change all default passwords
- [ ] Generate strong JWT secret (32+ characters)
- [ ] Configure HTTPS with valid certificates
- [ ] Set up firewall rules (limit port access)
- [ ] Enable audit logging
- [ ] Configure log rotation

#### Monitoring & Maintenance
- [ ] Set up PostgreSQL backups
- [ ] Configure log aggregation
- [ ] Monitor disk space usage
- [ ] Set up health check endpoints
- [ ] Configure alerting for service failures

#### Network Configuration
- [ ] Configure CIFS credentials for network shares
- [ ] Test network share connectivity
- [ ] Validate file permissions
- [ ] Set up VPN access if required

## 🛠️ Troubleshooting

### Common Issues

#### Authentication Problems
```bash
# Check login credentials
docker exec secretsnipe-visualizer cat /app/dashboard_security.json

# Verify authentication is enabled
grep -i auth .env
```

#### Database Connection Issues
```bash
# Check PostgreSQL status
docker logs secretsnipe-postgres

# Test database connectivity
docker exec secretsnipe-postgres psql -U secretsnipe -d secretsnipe -c "SELECT 1;"
```

#### CIFS Mount Problems
```bash
# Test CIFS connectivity
docker exec secretsnipe-visualizer mount | grep cifs

# Check CIFS credentials
docker exec secretsnipe-visualizer ls -la /monitor
```

#### Performance Issues
```bash
# Check container resource usage
docker stats

# Monitor database performance
docker exec secretsnipe-postgres psql -U secretsnipe -d secretsnipe -c "SELECT * FROM pg_stat_activity;"
```

### Log Analysis
```bash
# Dashboard logs
docker logs secretsnipe-visualizer --tail 50

# Database logs
docker logs secretsnipe-postgres --tail 20

# Webhook service logs
docker logs secretsnipe-webhook --tail 20

# Host monitor logs
docker logs secretsnipe-host-monitor --tail 20
```

## 📚 API Reference

### Dashboard Endpoints
- `GET /` - Main dashboard (requires authentication)
- `POST /login` - User authentication
- `POST /logout` - Session termination
- `GET /health` - Health check endpoint

### Data Export APIs
- `POST /_dash-update-component` - Dashboard data updates
- Custom report generation via dashboard interface

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/TimKenobi/Secret_Snipe.git
cd Secret_Snipe
pip install -r requirements.txt
```

### Code Style
- Python: PEP 8 compliance
- JavaScript: ESLint configuration
- CSS: BEM methodology

### Testing
```bash
# Run unit tests
python -m pytest tests/

# Security testing
python dashboard_security_audit.py
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **GitHub Issues**: https://github.com/TimKenobi/Secret_Snipe/issues
- **Wiki**: https://github.com/TimKenobi/Secret_Snipe/wiki
- **Documentation**: Complete documentation available in [`docs/`](../docs/) directory

---

*SecretSnipe - Keeping your secrets safe through continuous monitoring and detection*