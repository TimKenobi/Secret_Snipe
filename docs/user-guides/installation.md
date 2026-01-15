# Installation Guide

This guide provides step-by-step instructions for installing and setting up SecretSnipe in various environments.

## 🚀 Quick Start

### Prerequisites

**System Requirements:**
- **OS**: Linux, macOS, or Windows (with WSL2)
- **CPU**: 2+ cores recommended
- **RAM**: 4GB+ recommended (8GB for large scans)
- **Storage**: 10GB+ free space
- **Network**: Internet access for Docker image downloads

**Software Requirements:**
- **Docker**: Version 20.10+
- **Docker Compose**: Version 2.0+
- **Git**: For cloning the repository

### 1. Clone the Repository

```bash
# Clone the repository
git clone https://github.com/TimKenobi/Secret_Snipe.git
cd Secret_Snipe
```

### 2. Configure Environment

Create a `.env` file with your settings:

```bash
# Copy the example environment file
cp env_example .env

# Edit the .env file with your preferred editor
nano .env
```

**Minimal Configuration:**
```bash
# Database password (required)
POSTGRES_PASSWORD=your_secure_password_here

# Dashboard credentials (required)
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=SecretSnipe2024!

# Optional: Webhook for notifications
WEBHOOK_URL=https://your-teams-webhook-url
```

### 3. Start the Services

```bash
# Start all services
docker-compose up -d

# View startup logs
docker-compose logs -f
```

### 4. Access the Dashboard

- **URL**: http://localhost:8050
- **Username**: admin (or your configured username)
- **Password**: SecretSnipe2024! (or your configured password)

### 5. Run Your First Scan

```bash
# Scan a directory
docker-compose exec app python secret_snipe_pg.py /path/to/scan --project my-first-scan

# Or scan the included test data
docker-compose exec app python secret_snipe_pg.py /app/monitor_data --project test-scan
```

## 📋 Detailed Installation Methods

### Method 1: Docker Compose (Recommended)

This is the easiest and most reliable installation method.

#### Step 1: Prepare Environment

```bash
# Create project directory
mkdir secretsnipe && cd secretsnipe

# Clone repository
git clone https://github.com/TimKenobi/Secret_Snipe.git .
```

#### Step 2: Configure Services

Edit `docker-compose.yml` if needed:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: secretsnipe
      POSTGRES_USER: secretsnipe
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  app:
    image: secretsnipe:latest
    environment:
      - DB_HOST=postgres
      - DB_PASSWORD=${POSTGRES_PASSWORD}
      - REDIS_HOST=redis
      - DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
    ports:
      - "8050:8050"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./monitor:/monitor:ro
    depends_on:
      - postgres
      - redis

volumes:
  postgres_data:
  redis_data:
```

#### Step 3: Configure Environment Variables

Create `.env` file:

```bash
# Database
POSTGRES_PASSWORD=ChangeThisToASecurePassword123!

# Dashboard
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=AnotherSecurePassword456!

# Optional: Teams integration
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/your-webhook-id

# Optional: File scanning configuration
SUPPORTED_EXTENSIONS=.py,.js,.java,.pdf,.docx
EXCLUDED_DIRECTORIES=node_modules,.git,venv
```

#### Step 4: Start Services

```bash
# Start in detached mode
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs
```

#### Step 5: Initialize Database

The database will be automatically initialized on first startup. You can verify this by checking the logs:

```bash
docker-compose logs postgres
```

### Method 2: Manual Installation

For development or when Docker is not available.

#### Prerequisites

```bash
# Install Python 3.11+
python3 --version

# Install PostgreSQL
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib

# Install Redis
sudo apt-get install redis-server

# Install system dependencies
sudo apt-get install python3-dev build-essential
```

#### Step 1: Setup Python Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### Step 2: Setup PostgreSQL

```bash
# Create database and user
sudo -u postgres psql

# In PostgreSQL shell:
CREATE DATABASE secretsnipe;
CREATE USER secretsnipe WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE secretsnipe TO secretsnipe;
\q
```

#### Step 3: Setup Redis

```bash
# Start Redis service
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

#### Step 4: Configure Application

```bash
# Copy configuration
cp config.json config.local.json

# Edit configuration
nano config.local.json
```

#### Step 5: Initialize Database Schema

```bash
# Run schema setup
psql -h localhost -U secretsnipe -d secretsnipe -f database_schema.sql
```

#### Step 6: Start the Application

```bash
# Start the dashboard
python unified_visualizer_pg.py

# In another terminal, start scanning
python secret_snipe_pg.py /path/to/scan --project test
```

## 🔧 Advanced Configuration

### Production Docker Setup

For production deployments with enhanced security and monitoring:

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  # PostgreSQL with persistent storage
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: secretsnipe
      POSTGRES_USER: secretsnipe
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./database_schema.sql:/docker-entrypoint-initdb.d/init.sql
      - ./postgres.conf:/etc/postgresql/postgresql.conf
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U secretsnipe"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - secretsnipe_network

  # Redis with persistence and security
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - secretsnipe_network

  # SecretSnipe application
  app:
    image: secretsnipe:latest
    environment:
      - DB_HOST=postgres
      - DB_PASSWORD=${POSTGRES_PASSWORD}
      - REDIS_HOST=redis
      - DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
      - LOG_LEVEL=INFO
      - SCANNER_THREADS=8
      - WORKER_PROCESSES=4
    ports:
      - "8050:8050"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./monitor:/monitor:ro
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8050/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped
    networks:
      - secretsnipe_network

  # Nginx reverse proxy
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl/certs:ro
    depends_on:
      - app
    networks:
      - secretsnipe_network
    restart: unless-stopped

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

networks:
  secretsnipe_network:
    driver: bridge
```

### SSL/TLS Configuration

#### Using Let's Encrypt

```bash
# Install certbot
sudo apt-get install certbot

# Get SSL certificate
sudo certbot certonly --standalone -d your-domain.com

# Configure Nginx for SSL
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://secretsnipe_app:8050;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Using Self-Signed Certificates

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Mount certificates in Docker
volumes:
  - ./ssl/cert.pem:/etc/ssl/certs/secretsnipe.crt
  - ./ssl/key.pem:/etc/ssl/private/secretsnipe.key
```

### Network Share Integration

#### CIFS/SMB Share Setup

```bash
# Install CIFS utilities
sudo apt-get install cifs-utils

# Create credentials file
sudo mkdir -p /etc/samba
sudo tee /etc/samba/credentials > /dev/null <<EOF
username=YOUR_DOMAIN_USERNAME
password=YOUR_PASSWORD
domain=YOUR_DOMAIN
EOF
sudo chmod 600 /etc/samba/credentials

# Mount the share
sudo mkdir -p /mnt/secretsnipe_monitor
sudo mount -t cifs //server/share /mnt/secretsnipe_monitor \
  -o credentials=/etc/samba/credentials,vers=3.0,sec=ntlmssp

# Update Docker volumes
volumes:
  - /mnt/secretsnipe_monitor:/monitor:ro
```

#### Docker Compose with CIFS

```yaml
# docker-compose.cifs.yml
version: '3.8'

services:
  # CIFS mount service
  cifs-mount:
    image: alpine:latest
    command: sh -c "
      apk add --no-cache cifs-utils &&
      mkdir -p /mnt/secretsnipe &&
      mount -t cifs //${CIFS_SERVER}/${CIFS_SHARE} /mnt/secretsnipe
        -o username=${CIFS_USERNAME},password=${CIFS_PASSWORD},domain=${CIFS_DOMAIN},vers=3.0,sec=ntlmssp &&
      tail -f /dev/null
    "
    environment:
      - CIFS_SERVER=${CIFS_SERVER}
      - CIFS_SHARE=${CIFS_SHARE}
      - CIFS_USERNAME=${CIFS_USERNAME}
      - CIFS_PASSWORD=${CIFS_PASSWORD}
      - CIFS_DOMAIN=${CIFS_DOMAIN}
    volumes:
      - cifs_data:/mnt/secretsnipe
    privileged: true

  # SecretSnipe with CIFS access
  app:
    image: secretsnipe:latest
    volumes:
      - cifs_data:/monitor:ro
    depends_on:
      - cifs-mount

volumes:
  cifs_data:
```

### High Availability Setup

For production environments requiring high availability:

```yaml
# docker-compose.ha.yml
version: '3.8'

services:
  # Load balancer
  haproxy:
    image: haproxy:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    depends_on:
      - app1
      - app2

  # Application instances
  app1:
    image: secretsnipe:latest
    environment:
      - INSTANCE_ID=app1
    volumes:
      - ./data:/app/data
    networks:
      - app_network

  app2:
    image: secretsnipe:latest
    environment:
      - INSTANCE_ID=app2
    volumes:
      - ./data:/app/data
    networks:
      - app_network

  # Shared database
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: secretsnipe
      POSTGRES_USER: secretsnipe
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - db_network

  # Shared Redis
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    networks:
      - db_network

networks:
  app_network:
  db_network:

volumes:
  postgres_data:
  redis_data:
```

## 🔍 Verification Steps

### 1. Check Service Health

```bash
# Check all services are running
docker-compose ps

# Expected output:
#     Name                   Command               State                    Ports
# -----------------------------------------------------------------------------------
# secretsnipe_app_1      python run_secret_scanner_pg.py  Up      0.0.0.0:8050->8050/tcp
# secretsnipe_postgres_1 docker-entrypoint.sh postgres    Up      5432/tcp
# secretsnipe_redis_1    docker-entrypoint.sh redis ...   Up      6379/tcp
```

### 2. Verify Database Connection

```bash
# Test database connectivity
docker-compose exec postgres pg_isready -U secretsnipe

# Check database contents
docker-compose exec postgres psql -U secretsnipe -d secretsnipe -c "SELECT COUNT(*) FROM findings;"
```

### 3. Test Dashboard Access

```bash
# Test dashboard endpoint
curl -I http://localhost:8050

# Expected: HTTP/1.1 200 OK
```

### 4. Run Test Scan

```bash
# Run a test scan
docker-compose exec app python secret_snipe_pg.py /app/monitor_data --project test

# Check scan results
docker-compose exec postgres psql -U secretsnipe -d secretsnipe -c "SELECT * FROM findings LIMIT 5;"
```

## 🛠️ Troubleshooting Installation

### Common Issues

#### Docker Compose Fails to Start

```bash
# Check Docker and Docker Compose versions
docker --version
docker-compose --version

# Check available disk space
df -h

# Clean up Docker system
docker system prune -f
```

#### Database Connection Issues

```bash
# Check PostgreSQL logs
docker-compose logs postgres

# Test database connectivity
docker-compose exec postgres psql -U secretsnipe -d secretsnipe -c "SELECT version();"
```

#### Permission Issues

```bash
# Fix volume permissions
sudo chown -R 1000:1000 ./data ./logs

# Check Docker user permissions
docker-compose exec app id
```

#### Port Conflicts

```bash
# Check if ports are in use
netstat -tlnp | grep :8050

# Change ports in docker-compose.yml
ports:
  - "8051:8050"  # Change host port
```

## 📊 Post-Installation Tasks

### 1. Security Hardening

```bash
# Change default passwords
DASHBOARD_USERNAME=your_admin_user
DASHBOARD_PASSWORD=your_secure_password

# Enable SSL/TLS
# Configure firewall rules
# Setup log rotation
```

### 2. Performance Tuning

```bash
# Adjust scanner settings
SCANNER_THREADS=8
MAX_FILE_SIZE_MB=100

# Configure database pool
DB_MAX_CONNECTIONS=50

# Setup monitoring
# Configure backups
```

### 3. Backup Configuration

```bash
# Setup automated backups
0 2 * * * docker-compose exec postgres pg_dump -U secretsnipe secretsnipe > /backup/secretsnipe_$(date +\%Y\%m\%d).sql

# Test backup restoration
docker-compose exec postgres psql -U secretsnipe secretsnipe < /backup/secretsnipe_20250115.sql
```

### 4. Monitoring Setup

```bash
# Enable health checks
# Setup log aggregation
# Configure alerts
# Setup metrics collection
```

## 🔄 Upgrading

### Minor Version Updates

```bash
# Pull latest images
docker-compose pull

# Restart services
docker-compose up -d

# Check for database migrations
docker-compose exec app python -c "from database_manager import db_manager; db_manager.upgrade_schema()"
```

### Major Version Updates

```bash
# Backup data
docker-compose exec postgres pg_dump -U secretsnipe secretsnipe > backup.sql

# Update docker-compose.yml
# Update environment variables
# Test in staging environment first

# Deploy update
docker-compose down
docker-compose up -d

# Verify functionality
# Restore from backup if issues occur
```

## 📞 Support

If you encounter issues during installation:

1. **Check the logs**: `docker-compose logs`
2. **Verify configuration**: Compare with examples in this guide
3. **Test components individually**: Database, Redis, application
4. **Check system resources**: CPU, memory, disk space
5. **Review prerequisites**: Docker, Docker Compose versions

For additional help:
- **Documentation**: See `/docs` directory
- **Issues**: https://github.com/TimKenobi/Secret_Snipe/issues
- **Discussions**: https://github.com/TimKenobi/Secret_Snipe/discussions

---

*Last updated: September 19, 2025*