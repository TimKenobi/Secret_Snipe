# Docker Configuration Guide

This guide covers Docker deployment configurations for SecretSnipe in various environments.

## 🐳 Basic Docker Setup

### Single Container Setup

For development or small deployments:

```yaml
# docker-compose.yml
version: '3.8'

services:
  secretsnipe:
    image: secretsnipe:latest
    ports:
      - "8050:8050"
    environment:
      - DB_HOST=host.docker.internal
      - DB_PASSWORD=your_password
      - DASHBOARD_PASSWORD=admin_password
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./monitor:/monitor:ro
```

### Production Docker Setup

For production with separate services:

```yaml
# docker-compose.yml
version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: secretsnipe
      POSTGRES_USER: secretsnipe
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./database_schema.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - secretsnipe_network

  # Redis Cache
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - secretsnipe_network

  # SecretSnipe Application
  app:
    image: secretsnipe:latest
    environment:
      - DB_HOST=postgres
      - DB_PASSWORD=${POSTGRES_PASSWORD}
      - REDIS_HOST=redis
      - DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
      - LOG_LEVEL=INFO
    ports:
      - "8050:8050"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./monitor:/monitor:ro
    depends_on:
      - postgres
      - redis
    networks:
      - secretsnipe_network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:

networks:
  secretsnipe_network:
    driver: bridge
```

## 🔧 Advanced Docker Configurations

### Multi-Stage Build

For optimized production images:

```dockerfile
# Dockerfile
FROM python:3.11-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements-prod.txt .
RUN pip install --no-cache-dir -r requirements-prod.txt

# Production stage
FROM python:3.11-slim-bookworm AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    redis-tools \
    # OCR and image processing dependencies
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgthread-2.0-0 \
    libgtk-3-0 \
    libgdk-pixbuf2.0-0 \
    libcairo-gobject2 \
    libpango-1.0-0 \
    libatk1.0-0 \
    libcairo-gobject2 \
    libgtk-3-0 \
    libgdk-pixbuf2.0-0 \
    # Git for repository scanning
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r secretsnipe && \
    useradd --create-home --shell /bin/bash --gid secretsnipe --system secretsnipe

# Copy virtual environment
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=secretsnipe:secretsnipe . .

# Switch to non-root user
USER secretsnipe

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; from database_manager import db_manager; sys.exit(0 if db_manager.health_check() else 1)" || exit 1

# Default command
CMD ["python", "run_secret_scanner_pg.py", "/monitor"]
```

### Docker Compose with Monitoring

For production with monitoring and logging:

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  # PostgreSQL with monitoring
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
    networks:
      - secretsnipe_network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U secretsnipe"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Redis with persistence
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    networks:
      - secretsnipe_network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # SecretSnipe Application
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
    networks:
      - secretsnipe_network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2.0'
        reservations:
          memory: 1G
          cpus: '1.0'

  # Nginx Reverse Proxy
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

  # Monitoring with Prometheus
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    networks:
      - secretsnipe_network
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  # Grafana for dashboards
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    networks:
      - secretsnipe_network
    depends_on:
      - prometheus

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:

networks:
  secretsnipe_network:
    driver: bridge
```

## 🌐 Network Share Integration

### CIFS/SMB Share Mounting

For scanning network shares:

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
    networks:
      - secretsnipe_network
    privileged: true

  # SecretSnipe with CIFS access
  app:
    image: secretsnipe:latest
    environment:
      - DB_HOST=postgres
      - DB_PASSWORD=${POSTGRES_PASSWORD}
      - MONITOR_VOLUME=/mnt/secretsnipe:/monitor:ro
    volumes:
      - cifs_data:/monitor:ro
    depends_on:
      - cifs-mount
    networks:
      - secretsnipe_network

volumes:
  cifs_data:

networks:
  secretsnipe_network:
```

### Docker Host CIFS Mount

Alternative approach using host-mounted shares:

```bash
# On Docker host
sudo apt-get install cifs-utils
sudo mkdir -p /mnt/secretsnipe
sudo mount -t cifs //server/share /mnt/secretsnipe \
  -o credentials=/etc/samba/credentials,vers=3.0,sec=ntlmssp

# Then in docker-compose.yml
volumes:
  - /mnt/secretsnipe:/monitor:ro
```

## 🔒 Security Configurations

### Non-Root User

Running containers as non-root user:

```dockerfile
# Dockerfile
FROM python:3.11-slim-bookworm

# Create non-root user
RUN groupadd -r secretsnipe && \
    useradd --create-home --shell /bin/bash --gid secretsnipe --system secretsnipe && \
    mkdir -p /app /app/data /app/logs /tmp/secretsnipe && \
    chown -R secretsnipe:secretsnipe /app /tmp/secretsnipe

# Switch to non-root user
USER secretsnipe

WORKDIR /app
```

### Secrets Management

Using Docker secrets:

```yaml
# docker-compose.secrets.yml
version: '3.8'

secrets:
  db_password:
    file: ./secrets/db_password.txt
  dashboard_password:
    file: ./secrets/dashboard_password.txt

services:
  app:
    image: secretsnipe:latest
    secrets:
      - db_password
      - dashboard_password
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - DASHBOARD_PASSWORD_FILE=/run/secrets/dashboard_password
```

### Security Scanning

Adding security scanning to your pipeline:

```yaml
# docker-compose.security.yml
version: '3.8'

services:
  # Trivy security scanner
  trivy:
    image: aquasec/trivy:latest
    command: image --exit-code 1 --no-progress secretsnipe:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  # Clair vulnerability scanner
  clair:
    image: quay.io/projectquay/clair:latest
    ports:
      - "6060:6060"
    volumes:
      - clair_data:/clair-data

  # SecretSnipe with security context
  app:
    image: secretsnipe:latest
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

volumes:
  clair_data:
```

## 📊 Monitoring and Logging

### Centralized Logging

Using ELK stack for log aggregation:

```yaml
# docker-compose.logging.yml
version: '3.8'

services:
  # Elasticsearch
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.5.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - es_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"

  # Logstash
  logstash:
    image: docker.elastic.co/logstash/logstash:8.5.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    depends_on:
      - elasticsearch

  # Kibana
  kibana:
    image: docker.elastic.co/kibana/kibana:8.5.0
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

  # SecretSnipe with JSON logging
  app:
    image: secretsnipe:latest
    environment:
      - LOG_FORMAT=json
      - LOGSTASH_HOST=logstash
      - LOGSTASH_PORT=5044
    logging:
      driver: gelf
      options:
        gelf-address: "udp://logstash:12201"
        tag: "secretsnipe"

volumes:
  es_data:
```

### Prometheus Metrics

Adding Prometheus monitoring:

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  # Prometheus
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  # Node Exporter
  node-exporter:
    image: prom/node-exporter:latest
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'

  # SecretSnipe with metrics
  app:
    image: secretsnipe:latest
    environment:
      - METRICS_ENABLED=true
      - METRICS_PORT=9091
    ports:
      - "8050:8050"
      - "9091:9091"
```

## 🚀 Deployment Strategies

### Blue-Green Deployment

For zero-downtime deployments:

```yaml
# docker-compose.blue-green.yml
version: '3.8'

services:
  # Blue environment
  app-blue:
    image: secretsnipe:blue
    environment:
      - ENVIRONMENT=blue
    networks:
      - blue_network

  # Green environment
  app-green:
    image: secretsnipe:green
    environment:
      - ENVIRONMENT=green
    networks:
      - green_network

  # Nginx load balancer
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx-blue-green.conf:/etc/nginx/nginx.conf:ro
    networks:
      - blue_network
      - green_network

networks:
  blue_network:
  green_network:
```

### Kubernetes Deployment

For Kubernetes environments:

```yaml
# secretsnipe-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secretsnipe
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secretsnipe
  template:
    metadata:
      labels:
        app: secretsnipe
    spec:
      containers:
      - name: secretsnipe
        image: secretsnipe:latest
        ports:
        - containerPort: 8050
        env:
        - name: DB_HOST
          valueFrom:
            secretKeyRef:
              name: secretsnipe-secrets
              key: db-host
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: secretsnipe-secrets
              key: db-password
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8050
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8050
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 🔧 Troubleshooting Docker Issues

### Common Problems

1. **Container Won't Start**
   ```bash
   # Check logs
   docker-compose logs app

   # Check container status
   docker-compose ps

   # Check resource usage
   docker stats
   ```

2. **Database Connection Issues**
   ```bash
   # Test database connection
   docker-compose exec postgres pg_isready -U secretsnipe

   # Check database logs
   docker-compose logs postgres
   ```

3. **Permission Issues**
   ```bash
   # Fix volume permissions
   sudo chown -R 1000:1000 ./data ./logs

   # Check SELinux/AppArmor
   docker-compose exec app id
   ```

4. **Memory Issues**
   ```bash
   # Check memory usage
   docker stats

   # Adjust memory limits
   docker-compose.yml:
     deploy:
       resources:
         limits:
           memory: 2G
   ```

5. **Network Issues**
   ```bash
   # Check network connectivity
   docker-compose exec app ping postgres

   # Inspect networks
   docker network ls
   docker network inspect secretsnipe_default
   ```

### Performance Optimization

```yaml
# docker-compose.performance.yml
version: '3.8'

services:
  app:
    image: secretsnipe:latest
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '4.0'
        reservations:
          memory: 2G
          cpus: '2.0'
    environment:
      - SCANNER_THREADS=16
      - WORKER_PROCESSES=8
      - GUNICORN_WORKERS=8
      - BATCH_SIZE=2000
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8050/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

---

*Last updated: September 19, 2025*