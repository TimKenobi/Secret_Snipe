# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with SecretSnipe.

## 🔍 General Troubleshooting Steps

### 1. Check System Status

```bash
# Check all services
docker-compose ps

# View logs
docker-compose logs -f

# Check resource usage
docker stats

# Test basic connectivity
curl http://localhost:8050/health
```

### 2. Verify Configuration

```bash
# Validate environment variables
python -c "import os; [print(f'{k}={v}') for k,v in os.environ.items() if 'DB_' in k or 'REDIS_' in k]"

# Test configuration loading
python -c "from config import Config; c = Config(); print('Config loaded successfully')"
```

### 3. Check Dependencies

```bash
# Verify Python packages
python -c "import psycopg2, redis, PyMuPDF, easyocr; print('All dependencies OK')"

# Check database connectivity
python -c "from database_manager import db_manager; print(db_manager.health_check())"
```

## 🗄️ Database Issues

### Connection Problems

**Symptoms:**
- "Connection refused" errors
- "FATAL: password authentication failed" errors
- Dashboard shows database connection errors

**Solutions:**

1. **Check Database Service**
   ```bash
   # Verify PostgreSQL is running
   docker-compose ps postgres

   # Check database logs
   docker-compose logs postgres
   ```

2. **Verify Connection Parameters**
   ```bash
   # Test connection from container
   docker-compose exec app python -c "
   import psycopg2
   conn = psycopg2.connect(
       host='postgres',
       database='secretsnipe',
       user='secretsnipe',
       password='your_password'
   )
   print('Database connection successful')
   "
   ```

3. **Check Environment Variables**
   ```bash
   # Verify DB_* variables are set
   docker-compose exec app env | grep DB_
   ```

4. **Network Connectivity**
   ```bash
   # Test network connectivity
   docker-compose exec app ping postgres

   # Check Docker network
   docker network ls
   docker network inspect secretsnipe_default
   ```

### Performance Issues

**Symptoms:**
- Slow query responses
- High memory usage
- Database connection pool exhausted

**Solutions:**

1. **Optimize Connection Pool**
   ```sql
   -- Check active connections
   SELECT count(*) FROM pg_stat_activity WHERE datname = 'secretsnipe';

   -- Adjust pool settings in config
   db_connection_pool_size: 20
   db_max_connections: 100
   ```

2. **Database Indexing**
   ```sql
   -- Create performance indexes
   CREATE INDEX CONCURRENTLY idx_findings_composite
   ON findings(project_id, scan_session_id, severity, first_seen DESC);

   CREATE INDEX CONCURRENTLY idx_findings_file
   ON findings(file_path, line_number);
   ```

3. **Query Optimization**
   ```sql
   -- Analyze slow queries
   EXPLAIN ANALYZE SELECT * FROM findings WHERE project_id = '123';

   -- Add composite indexes for common query patterns
   CREATE INDEX idx_findings_project_severity
   ON findings(project_id, severity);
   ```

## 🔄 Redis Issues

### Connection Problems

**Symptoms:**
- "ConnectionError: Error 111 connecting" errors
- Redis cache not working
- Session data not persisting

**Solutions:**

1. **Check Redis Service**
   ```bash
   # Verify Redis is running
   docker-compose ps redis

   # Test Redis connectivity
   docker-compose exec redis redis-cli ping
   ```

2. **Verify Configuration**
   ```bash
   # Check Redis environment variables
   docker-compose exec app env | grep REDIS_

   # Test Redis connection from app
   docker-compose exec app python -c "
   import redis
   r = redis.Redis(host='redis', port=6379)
   r.set('test', 'value')
   print('Redis connection successful')
   "
   ```

3. **Memory Issues**
   ```bash
   # Check Redis memory usage
   docker-compose exec redis redis-cli info memory

   # Configure Redis memory limits
   redis.conf:
   maxmemory 512mb
   maxmemory-policy allkeys-lru
   ```

## 📁 File Scanning Issues

### File Access Problems

**Symptoms:**
- "Permission denied" errors
- Files not being scanned
- OCR not working on images

**Solutions:**

1. **Check Volume Mounts**
   ```bash
   # Verify volume mappings
   docker-compose exec app ls -la /monitor

   # Test file access
   docker-compose exec app cat /monitor/test.txt
   ```

2. **File Permissions**
   ```bash
   # Check file permissions
   ls -la /path/to/scan/directory

   # Fix permissions if needed
   sudo chown -R 1000:1000 /path/to/scan/directory
   ```

3. **CIFS/SMB Issues**
   ```bash
   # Test CIFS mount
   sudo mount -t cifs //server/share /mnt/test \
     -o username=user,password=pass,domain=domain

   # Check mount options
   mount | grep cifs
   ```

### OCR Problems

**Symptoms:**
- Images not being processed
- OCR returning empty results
- "OCR library not found" errors

**Solutions:**

1. **Check OCR Dependencies**
   ```bash
   # Verify OCR libraries are installed
   docker-compose exec app python -c "
   import easyocr
   reader = easyocr.Reader(['en'])
   print('OCR libraries OK')
   "
   ```

2. **Test OCR Functionality**
   ```bash
   # Test OCR on a sample image
   docker-compose exec app python -c "
   import easyocr
   reader = easyocr.Reader(['en'])
   result = reader.readtext('/path/to/test/image.png')
   print('OCR result:', result)
   "
   ```

3. **Configure OCR Settings**
   ```json
   {
     "ocr": {
       "enabled": true,
       "languages": ["en", "es"],
       "timeout": 30,
       "confidence_threshold": 0.6
     }
   }
   ```

## 🌐 Network and Webhook Issues

### Webhook Delivery Problems

**Symptoms:**
- Webhooks not being sent
- "Connection timeout" errors
- Webhook endpoints not receiving notifications

**Solutions:**

1. **Test Webhook Configuration**
   ```bash
   # Test webhook URL
   curl -X POST https://your-webhook-endpoint.com/webhook \
     -H "Content-Type: application/json" \
     -d '{"test": "message"}'
   ```

2. **Check Webhook Logs**
   ```bash
   # View webhook-related logs
   docker-compose logs | grep webhook

   # Enable webhook debugging
   environment:
     - LOG_LEVEL=DEBUG
   ```

3. **Network Connectivity**
   ```bash
   # Test outbound connectivity
   docker-compose exec app curl -I https://your-webhook-endpoint.com

   # Check DNS resolution
   docker-compose exec app nslookup your-webhook-endpoint.com
   ```

### Microsoft Teams Integration

**Symptoms:**
- Teams messages not being delivered
- Authentication errors
- Message formatting issues

**Solutions:**

1. **Verify Teams Webhook URL**
   ```bash
   # Test Teams webhook
   curl -X POST https://outlook.office.com/webhook/your-webhook-id \
     -H "Content-Type: application/json" \
     -d '{"text": "Test message"}'
   ```

2. **Check Teams Configuration**
   ```json
   {
     "teams": {
       "webhook_url": "https://outlook.office.com/webhook/...",
       "message_template": "🚨 SecretSnipe Alert: {finding_count} findings",
       "weekly_report": true
     }
   }
   ```

## 🚨 Scanner Performance Issues

### Slow Scanning

**Symptoms:**
- Scans taking too long
- High CPU/memory usage
- Scanner threads not utilizing all cores

**Solutions:**

1. **Optimize Thread Count**
   ```json
   {
     "scanner": {
       "threads": 8,
       "timeout_seconds": 300,
       "max_file_size_mb": 50
     }
   }
   ```

2. **File Type Filtering**
   ```bash
   # Limit file types to scan
   SUPPORTED_EXTENSIONS=.py,.js,.java,.pdf
   EXCLUDED_EXTENSIONS=.exe,.dll,.bin
   ```

3. **Memory Optimization**
   ```bash
   # Adjust memory limits
   docker-compose.yml:
     deploy:
       resources:
         limits:
           memory: 4G
           cpus: '4.0'
   ```

### False Positives

**Symptoms:**
- Too many false positive detections
- Legitimate code flagged as secrets

**Solutions:**

1. **Adjust Detection Patterns**
   ```json
   {
     "signatures": {
       "aws_api_key": {
         "pattern": "AKIA[0-9A-Z]{16}",
         "confidence": 0.8,
         "context_required": true
       }
     }
   }
   ```

2. **Context Analysis**
   ```python
   # Enable context analysis
   context_analysis: true
   context_window: 3
   ```

3. **Whitelist Configuration**
   ```json
   {
     "whitelist": {
       "patterns": [
         "test.*key",
         "example.*token"
       ],
       "files": [
         "**/test/**",
         "**/example/**"
       ]
     }
   }
   ```

## 📊 Dashboard Issues

### Login Problems

**Symptoms:**
- Cannot log into dashboard
- "Invalid credentials" errors
- Session timeout issues

**Solutions:**

1. **Verify Credentials**
   ```bash
   # Check environment variables
   docker-compose exec app env | grep DASHBOARD_

   # Reset password if needed
   docker-compose exec app python -c "
   from config import Config
   c = Config()
   print('Dashboard user:', c.dashboard_username)
   "
   ```

2. **Session Configuration**
   ```json
   {
     "dashboard": {
       "session_timeout": 480,
       "secret_key": "your-secret-key"
     }
   }
   ```

### Display Issues

**Symptoms:**
- Charts not loading
- Data not refreshing
- UI performance problems

**Solutions:**

1. **Check Browser Console**
   ```
   # Open browser developer tools
   # Check for JavaScript errors
   # Verify API endpoints are accessible
   ```

2. **API Connectivity**
   ```bash
   # Test API endpoints
   curl http://localhost:8050/api/v1/projects

   # Check API logs
   docker-compose logs | grep api
   ```

3. **Database Queries**
   ```sql
   -- Check for slow dashboard queries
   SELECT query, total_time, calls
   FROM pg_stat_statements
   ORDER BY total_time DESC
   LIMIT 10;
   ```

## 🔧 System Resource Issues

### Memory Problems

**Symptoms:**
- Out of memory errors
- Container restarts
- Slow performance

**Solutions:**

1. **Monitor Memory Usage**
   ```bash
   # Check memory usage
   docker stats

   # Adjust memory limits
   docker-compose.yml:
     deploy:
       resources:
         limits:
           memory: 4G
         reservations:
           memory: 2G
   ```

2. **Optimize Memory Settings**
   ```json
   {
     "memory": {
       "limit_mb": 4096,
       "batch_size": 1000,
       "cleanup_interval": 300
     }
   }
   ```

### Disk Space Issues

**Symptoms:**
- "No space left on device" errors
- Database growth issues
- Log files consuming space

**Solutions:**

1. **Monitor Disk Usage**
   ```bash
   # Check disk usage
   df -h

   # Check Docker volumes
   docker system df
   ```

2. **Log Rotation**
   ```bash
   # Configure log rotation
   LOG_MAX_SIZE_MB=100
   LOG_BACKUP_COUNT=5
   ```

3. **Database Cleanup**
   ```sql
   -- Archive old findings
   CREATE TABLE findings_archive AS
   SELECT * FROM findings
   WHERE first_seen < NOW() - INTERVAL '90 days';

   DELETE FROM findings
   WHERE first_seen < NOW() - INTERVAL '90 days';
   ```

## 🔍 Advanced Debugging

### Enable Debug Logging

```bash
# Set debug logging
LOG_LEVEL=DEBUG

# Enable SQL query logging
SQLALCHEMY_ECHO=true

# Enable webhook debugging
WEBHOOK_DEBUG=true
```

### Performance Profiling

```python
# Add profiling to scanner
import cProfile
import pstats

def profile_scanner():
    profiler = cProfile.Profile()
    profiler.enable()

    # Run scanner
    scanner.scan('/path/to/scan')

    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative').print_stats(20)
```

### Memory Leak Detection

```python
# Monitor memory usage
import tracemalloc
import gc

tracemalloc.start()

# Run scanner
scanner.scan('/path/to/scan')

current, peak = tracemalloc.get_traced_memory()
print(f"Current memory usage: {current / 1024 / 1024:.1f} MB")
print(f"Peak memory usage: {peak / 1024 / 1024:.1f} MB")

# Get memory usage by object
snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics('lineno')
for stat in top_stats[:10]:
    print(stat)
```

## 🚑 Emergency Recovery

### Database Recovery

```bash
# Stop all services
docker-compose down

# Backup current database
docker-compose exec postgres pg_dump -U secretsnipe secretsnipe > backup.sql

# Restore from backup
docker-compose exec -T postgres psql -U secretsnipe secretsnipe < backup.sql

# Start services
docker-compose up -d
```

### Configuration Reset

```bash
# Reset to default configuration
cp config.json.backup config.json

# Clear Redis cache
docker-compose exec redis redis-cli FLUSHALL

# Restart services
docker-compose restart
```

### Complete System Reset

```bash
# Stop and remove all containers
docker-compose down -v

# Remove Docker volumes
docker volume rm $(docker volume ls -q | grep secretsnipe)

# Clean up Docker system
docker system prune -f

# Rebuild and restart
docker-compose up -d --build
```

## 📞 Getting Help

If you can't resolve an issue:

1. **Collect Diagnostic Information**
   ```bash
   # System information
   uname -a
   docker --version
   docker-compose --version

   # Service status
   docker-compose ps
   docker-compose logs > logs.txt

   # Configuration
   cat .env
   cat config.json
   ```

2. **Check GitHub Issues**
   - Search existing issues: https://github.com/TimKenobi/Secret_Snipe/issues
   - Create new issue with diagnostic information

3. **Community Support**
   - GitHub Discussions: https://github.com/TimKenobi/Secret_Snipe/discussions
   - Wiki: https://github.com/TimKenobi/Secret_Snipe/wiki

---

*Last updated: September 19, 2025*