# Environment Variables Configuration

This guide covers all environment variables used to configure SecretSnipe.

## 📋 Core Configuration

### Database Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DB_HOST` | PostgreSQL host | `localhost` | Yes |
| `DB_PORT` | PostgreSQL port | `5432` | No |
| `DB_NAME` | Database name | `secretsnipe` | No |
| `DB_USER` | Database user | `secretsnipe` | No |
| `DB_PASSWORD` | Database password | - | Yes |
| `DB_SSL_MODE` | SSL mode (disable/require/verify-ca/verify-full) | `prefer` | No |
| `DB_CONNECTION_TIMEOUT` | Connection timeout (seconds) | `30` | No |
| `DB_MAX_CONNECTIONS` | Maximum connections | `20` | No |

**Example:**
```bash
DB_HOST=postgres.company.com
DB_PORT=5432
DB_NAME=secretsnipe_prod
DB_USER=secretsnipe_app
DB_PASSWORD=your_secure_password
DB_SSL_MODE=require
```

### Redis Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `REDIS_HOST` | Redis host | `localhost` | No |
| `REDIS_PORT` | Redis port | `6379` | No |
| `REDIS_DB` | Redis database number | `0` | No |
| `REDIS_PASSWORD` | Redis password | - | No |
| `REDIS_SSL` | Enable SSL for Redis | `false` | No |
| `REDIS_MAX_CONNECTIONS` | Maximum Redis connections | `20` | No |
| `REDIS_SOCKET_TIMEOUT` | Socket timeout (seconds) | `5` | No |

**Example:**
```bash
REDIS_HOST=redis-cluster.company.com
REDIS_PORT=6379
REDIS_PASSWORD=redis_secure_password
REDIS_SSL=true
```

## 🌐 Web Server Configuration

### Dashboard Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DASHBOARD_HOST` | Dashboard bind address | `0.0.0.0` | No |
| `DASHBOARD_PORT` | Dashboard port | `8050` | No |
| `DASHBOARD_DEBUG` | Enable debug mode | `false` | No |
| `DASHBOARD_USERNAME` | Dashboard username | `admin` | No |
| `DASHBOARD_PASSWORD` | Dashboard password | - | Yes |
| `DASHBOARD_SESSION_TIMEOUT` | Session timeout (minutes) | `480` | No |

**Example:**
```bash
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8050
DASHBOARD_USERNAME=security_admin
DASHBOARD_PASSWORD=SecurePass123!
DASHBOARD_DEBUG=false
```

### API Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `API_HOST` | API server bind address | `0.0.0.0` | No |
| `API_PORT` | API server port | `8000` | No |
| `API_CORS_ORIGINS` | CORS allowed origins | `*` | No |
| `API_RATE_LIMIT` | API rate limit (requests/minute) | `1000` | No |

## 🔍 Scanner Configuration

### File Processing

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SUPPORTED_EXTENSIONS` | Comma-separated file extensions | See below | No |
| `EXCLUDED_EXTENSIONS` | Extensions to exclude | - | No |
| `EXCLUDED_DIRECTORIES` | Directories to exclude | `node_modules,.git,venv` | No |
| `MAX_FILE_SIZE_MB` | Maximum file size to scan | `100` | No |
| `MAX_SCAN_DEPTH` | Maximum directory depth | `10` | No |

**Default Supported Extensions:**
```
.py,.js,.ts,.java,.cpp,.c,.h,.php,.rb,.go,.rs,.swift,.kt,.scala,.clj,.hs,.ml,.txt,.md,.json,.xml,.yaml,.yml,.toml,.ini,.cfg,.conf,.properties,.env,.sh,.bat,.ps1,.pdf,.docx,.xlsx,.pptx,.doc,.xls,.ppt,.jpg,.jpeg,.png,.bmp,.tiff,.gif,.webp,.zip,.tar,.gz,.bz2,.rar,.7z
```

**Example:**
```bash
SUPPORTED_EXTENSIONS=.py,.js,.java,.pdf,.docx
EXCLUDED_EXTENSIONS=.exe,.dll,.bin
EXCLUDED_DIRECTORIES=node_modules,.git,venv,__pycache__,build,dist
MAX_FILE_SIZE_MB=50
```

### OCR Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ENABLE_OCR` | Enable OCR for images | `true` | No |
| `OCR_LANGUAGES` | OCR languages (comma-separated) | `en` | No |
| `OCR_TIMEOUT` | OCR timeout per image (seconds) | `30` | No |
| `OCR_CONFIDENCE_THRESHOLD` | Minimum OCR confidence | `0.6` | No |

**Example:**
```bash
ENABLE_OCR=true
OCR_LANGUAGES=en,es,fr,de
OCR_TIMEOUT=60
OCR_CONFIDENCE_THRESHOLD=0.7
```

### Performance Tuning

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SCANNER_THREADS` | Number of scanner threads | `4` | No |
| `SCANNER_TIMEOUT` | Scan timeout (seconds) | `300` | No |
| `WORKER_PROCESSES` | Number of worker processes | `2` | No |
| `BATCH_SIZE` | Database batch size | `1000` | No |
| `MEMORY_LIMIT_MB` | Memory limit per process | `1024` | No |

**Example:**
```bash
SCANNER_THREADS=8
SCANNER_TIMEOUT=600
WORKER_PROCESSES=4
BATCH_SIZE=500
MEMORY_LIMIT_MB=2048
```

## 🔔 Notification Configuration

### Webhook Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `WEBHOOK_URL` | Webhook endpoint URL | - | No |
| `WEBHOOK_METHOD` | HTTP method (GET/POST/PUT) | `POST` | No |
| `WEBHOOK_TIMEOUT` | Webhook timeout (seconds) | `30` | No |
| `WEBHOOK_RETRY_ATTEMPTS` | Retry attempts | `3` | No |
| `WEBHOOK_RETRY_DELAY` | Retry delay (seconds) | `5` | No |
| `WEBHOOK_AUTH_TOKEN` | Authentication token | - | No |
| `WEBHOOK_AUTH_TYPE` | Auth type (Bearer/Basic) | `Bearer` | No |

**Example:**
```bash
WEBHOOK_URL=https://api.company.com/webhooks/secretsnipe
WEBHOOK_METHOD=POST
WEBHOOK_TIMEOUT=60
WEBHOOK_RETRY_ATTEMPTS=5
WEBHOOK_AUTH_TOKEN=your-webhook-token
WEBHOOK_AUTH_TYPE=Bearer
```

### Microsoft Teams Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `TEAMS_WEBHOOK_URL` | Teams webhook URL | - | No |
| `TEAMS_MESSAGE_TEMPLATE` | Custom message template | - | No |
| `TEAMS_WEEKLY_REPORT` | Enable weekly reports | `true` | No |
| `TEAMS_WEEKLY_REPORT_TIME` | Weekly report time (HH:MM) | `09:00` | No |

**Example:**
```bash
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/your-webhook-id
TEAMS_MESSAGE_TEMPLATE="🚨 SecretSnipe Alert: {finding_count} new {severity} findings in {project_name}"
TEAMS_WEEKLY_REPORT=true
TEAMS_WEEKLY_REPORT_TIME=09:00
```

### Email Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SMTP_HOST` | SMTP server host | - | No |
| `SMTP_PORT` | SMTP server port | `587` | No |
| `SMTP_USERNAME` | SMTP username | - | No |
| `SMTP_PASSWORD` | SMTP password | - | No |
| `SMTP_TLS` | Enable TLS | `true` | No |
| `EMAIL_FROM` | From email address | - | No |
| `EMAIL_TO` | To email addresses (comma-separated) | - | No |

**Example:**
```bash
SMTP_HOST=smtp.company.com
SMTP_PORT=587
SMTP_USERNAME=secretsnipe@company.com
SMTP_PASSWORD=your-smtp-password
SMTP_TLS=true
EMAIL_FROM=secretsnipe@company.com
EMAIL_TO=security@company.com,devops@company.com
```

## 🔐 Security Configuration

### Authentication

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Flask secret key | Auto-generated | No |
| `JWT_SECRET_KEY` | JWT signing key | Auto-generated | No |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | JWT expiration | `30` | No |
| `BCRYPT_ROUNDS` | Password hashing rounds | `12` | No |

### Encryption

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ENCRYPTION_KEY` | Database encryption key | - | No |
| `ENCRYPT_SENSITIVE_DATA` | Enable data encryption | `false` | No |
| `ENCRYPTION_ALGORITHM` | Encryption algorithm | `AES-256-GCM` | No |

**Example:**
```bash
SECRET_KEY=your-very-secure-secret-key-here
ENCRYPT_SENSITIVE_DATA=true
ENCRYPTION_KEY=your-32-byte-encryption-key
```

## 📊 Logging Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LOG_LEVEL` | Logging level (DEBUG/INFO/WARNING/ERROR) | `INFO` | No |
| `LOG_FILE` | Log file path | `secretsnipe.log` | No |
| `LOG_MAX_SIZE_MB` | Max log file size | `100` | No |
| `LOG_BACKUP_COUNT` | Number of backup files | `5` | No |
| `LOG_FORMAT` | Log format string | See below | No |

**Default Log Format:**
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

**Example:**
```bash
LOG_LEVEL=DEBUG
LOG_FILE=/var/log/secretsnipe/secretsnipe.log
LOG_MAX_SIZE_MB=500
LOG_BACKUP_COUNT=10
```

## 📁 Volume Configuration

### Docker Volumes

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MONITOR_VOLUME` | Monitor volume mapping | - | No |
| `HOST_MONITOR_VOLUME` | Host monitor volume | - | No |
| `DATA_VOLUME` | Data volume mapping | `./data:/app/data` | No |
| `LOGS_VOLUME` | Logs volume mapping | `./logs:/app/logs` | No |

**Example:**
```bash
MONITOR_VOLUME=//server/share:/monitor:ro
HOST_MONITOR_VOLUME=//server/share:/app/host_monitor:ro
DATA_VOLUME=./data:/app/data
LOGS_VOLUME=./logs:/app/logs
```

### CIFS Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `CIFS_USERNAME` | CIFS username | - | No |
| `CIFS_PASSWORD` | CIFS password | - | No |
| `CIFS_DOMAIN` | CIFS domain | - | No |
| `CIFS_MOUNT_OPTIONS` | Additional mount options | `vers=3.0,sec=ntlmssp` | No |

**Example:**
```bash
CIFS_USERNAME=domain\\username
CIFS_PASSWORD=your-password
CIFS_DOMAIN=COMPANY
CIFS_MOUNT_OPTIONS=vers=3.0,sec=ntlmssp,iocharset=utf8
```

## 🔧 Advanced Configuration

### Performance Optimization

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `POSTGRES_MAX_CONNECTIONS` | PostgreSQL max connections | `100` | No |
| `REDIS_MAX_CONNECTIONS` | Redis max connections | `50` | No |
| `GUNICORN_WORKERS` | Gunicorn worker count | `4` | No |
| `GUNICORN_WORKER_TIMEOUT` | Worker timeout | `30` | No |
| `GUNICORN_MAX_REQUESTS` | Max requests per worker | `1000` | No |

### Monitoring

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `METRICS_ENABLED` | Enable Prometheus metrics | `false` | No |
| `METRICS_PORT` | Metrics port | `9090` | No |
| `HEALTH_CHECK_INTERVAL` | Health check interval | `30` | No |

### Development

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DEBUG` | Enable debug mode | `false` | No |
| `RELOAD` | Enable auto-reload | `false` | No |
| `TESTING` | Enable testing mode | `false` | No |

## 📄 Complete Example

Here's a complete `.env` file example for production deployment:

```bash
# =============================================================================
# SecretSnipe Production Configuration
# =============================================================================

# Database Configuration
DB_HOST=postgres-prod.company.com
DB_PORT=5432
DB_NAME=secretsnipe_prod
DB_USER=secretsnipe_app
DB_PASSWORD=your-secure-database-password
DB_SSL_MODE=require
DB_MAX_CONNECTIONS=50

# Redis Configuration
REDIS_HOST=redis-cluster.company.com
REDIS_PORT=6379
REDIS_PASSWORD=redis-secure-password
REDIS_SSL=true
REDIS_MAX_CONNECTIONS=20

# Dashboard Configuration
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8050
DASHBOARD_USERNAME=security_admin
DASHBOARD_PASSWORD=SecurePass123!
DASHBOARD_DEBUG=false

# Scanner Configuration
SUPPORTED_EXTENSIONS=.py,.js,.java,.pdf,.docx,.jpg,.png,.zip
EXCLUDED_DIRECTORIES=node_modules,.git,venv,__pycache__
MAX_FILE_SIZE_MB=100
SCANNER_THREADS=8
ENABLE_OCR=true
OCR_LANGUAGES=en,es,fr

# Webhook Configuration
WEBHOOK_URL=https://api.company.com/webhooks/secretsnipe
WEBHOOK_AUTH_TOKEN=your-webhook-token

# Teams Integration
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/your-webhook-id
TEAMS_WEEKLY_REPORT=true

# Security
SECRET_KEY=your-very-secure-secret-key-here
ENCRYPT_SENSITIVE_DATA=true

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/secretsnipe/secretsnipe.log

# Volumes
MONITOR_VOLUME=//fileserver.company.com/secrets:/monitor:ro
CIFS_USERNAME=COMPANY\\secretsnipe
CIFS_PASSWORD=your-cifs-password
CIFS_DOMAIN=COMPANY
```

## 🔍 Validation

You can validate your configuration using the built-in validator:

```bash
# Validate configuration
python -c "from config import Config; c = Config(); print('Configuration valid')"

# Check environment variables
python -c "import os; [print(f'{k}={v}') for k,v in os.environ.items() if k.startswith(('DB_', 'REDIS_', 'DASHBOARD_'))]"
```

## 🚨 Common Issues

1. **Database Connection Issues**
   - Check `DB_HOST`, `DB_PORT`, `DB_PASSWORD`
   - Verify SSL settings match database configuration
   - Check firewall rules

2. **Redis Connection Issues**
   - Verify `REDIS_HOST` and `REDIS_PORT`
   - Check `REDIS_PASSWORD` if authentication is required
   - Ensure Redis is running and accessible

3. **File Access Issues**
   - Check volume mappings in Docker
   - Verify CIFS credentials for network shares
   - Check file permissions

4. **Performance Issues**
   - Adjust `SCANNER_THREADS` based on system resources
   - Increase `DB_MAX_CONNECTIONS` for high load
   - Monitor memory usage with `MEMORY_LIMIT_MB`

---

*Last updated: September 19, 2025*