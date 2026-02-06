# SecretSnipe Enterprise Agent Architecture

## Overview
Full-featured, professional-grade agent management system with:
- **3 Scanners**: Gitleaks, Trufflehog, Custom Regex
- **File Watching**: Real-time monitoring with incremental scanning
- **Resource Management**: CPU/Memory throttling
- **Remote Management**: Logs, Config, Updates, Schedules

---

## Agent Features

### 1. Multi-Scanner Integration
```
┌─────────────────────────────────────────────────────────┐
│                   SecretSnipe Agent                     │
├──────────────┬──────────────┬──────────────────────────┤
│   Gitleaks   │  Trufflehog  │    Custom Scanner        │
│  (subprocess)│  (subprocess)│    (built-in regex)      │
├──────────────┴──────────────┴──────────────────────────┤
│              Finding Deduplicator/Merger               │
├────────────────────────────────────────────────────────┤
│                  Results Submission                    │
└────────────────────────────────────────────────────────┘
```

### 2. Operating Modes
- **Idle/Watch Mode**: Monitor paths for file changes, scan only changed files
- **Scheduled Mode**: Execute full scans at configured times
- **On-Demand Mode**: Execute jobs pushed from manager
- **Continuous Mode**: Full scan with configurable interval

### 3. Resource Limits
- Max CPU percentage (default: 50%)
- Max Memory usage (default: 500MB)
- Max concurrent file scans
- IO throttling for large directories
- Scan pausing when system is busy

### 4. Log Streaming
- Local log rotation (keep 7 days)
- Stream logs to manager on request
- Different log levels: DEBUG, INFO, WARNING, ERROR
- Structured JSON logs for parsing

### 5. Auto-Update
- Check for updates on heartbeat
- Download update package from manager
- Backup current version
- Apply update and restart
- Rollback on failure

---

## Manager API Endpoints

### Existing (Enhanced)
- `POST /api/v1/agents/register` - Register with capabilities
- `POST /api/v1/agents/heartbeat` - Heartbeat with update check
- `GET /api/v1/jobs/poll` - Poll for pending jobs
- `POST /api/v1/findings/submit` - Submit findings

### New Endpoints
```
# Logs
GET  /api/v1/agents/{id}/logs?lines=100&level=INFO
POST /api/v1/agents/{id}/logs/stream  (WebSocket upgrade)

# Schedules
GET    /api/v1/schedules                  - List all schedules
POST   /api/v1/schedules                  - Create schedule
GET    /api/v1/schedules/{id}             - Get schedule
PUT    /api/v1/schedules/{id}             - Update schedule
DELETE /api/v1/schedules/{id}             - Delete schedule
GET    /api/v1/agents/{id}/schedules      - Get agent's schedules

# Configuration
GET  /api/v1/agents/{id}/config           - Get agent config
PUT  /api/v1/agents/{id}/config           - Push config update
POST /api/v1/agents/{id}/restart          - Request agent restart

# Updates
GET  /api/v1/updates/latest               - Get latest agent version
POST /api/v1/updates/deploy               - Deploy update to agents
GET  /api/v1/agents/{id}/update-status    - Check update status

# Watch Paths
GET  /api/v1/agents/{id}/watch-paths      - Get watched paths
PUT  /api/v1/agents/{id}/watch-paths      - Update watched paths
```

---

## Database Schema

### agent_logs
```sql
CREATE TABLE agent_logs (
    id SERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    level VARCHAR(10),  -- DEBUG, INFO, WARNING, ERROR
    message TEXT,
    context JSONB,  -- Additional structured data
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_agent_logs_agent_ts ON agent_logs(agent_id, timestamp DESC);
```

### scan_schedules
```sql
CREATE TABLE scan_schedules (
    schedule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(agent_id),
    name VARCHAR(255),
    scan_paths JSONB,
    cron_expression VARCHAR(100),  -- "0 2 * * *" = 2 AM daily
    enabled BOOLEAN DEFAULT true,
    scanner_config JSONB,  -- Which scanners, options
    last_run TIMESTAMPTZ,
    next_run TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### agent_configs
```sql
CREATE TABLE agent_configs (
    config_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(agent_id) UNIQUE,
    config JSONB NOT NULL,  -- Full agent configuration
    version INTEGER DEFAULT 1,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### agent_updates
```sql
CREATE TABLE agent_updates (
    update_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version VARCHAR(20),
    release_notes TEXT,
    package_url TEXT,
    package_hash VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE agent_update_status (
    id SERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id),
    update_id UUID REFERENCES agent_updates(update_id),
    status VARCHAR(20),  -- pending, downloading, applying, completed, failed
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);
```

### watch_paths
```sql
CREATE TABLE agent_watch_paths (
    id SERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id),
    path TEXT NOT NULL,
    recursive BOOLEAN DEFAULT true,
    file_patterns JSONB,  -- ["*.py", "*.js", "*.env"]
    exclude_patterns JSONB,  -- ["node_modules", ".git"]
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## Dashboard UI Tabs

### 1. Agents Overview (existing, enhanced)
- Agent list with status, last heartbeat, resources
- Quick actions: Start scan, View logs, Configure

### 2. Logs Viewer (new)
- Select agent from dropdown
- Real-time log streaming
- Filter by level, search by text
- Download logs

### 3. Schedules (new)
- List all schedules across agents
- Create/Edit schedule with cron builder
- Enable/Disable schedules
- View last run, next run

### 4. Configuration (new)
- Agent config editor (JSON/Form)
- Push config to agent(s)
- Config templates
- Bulk configuration

### 5. Updates (new)
- Upload new agent version
- Deploy to selected agents
- View deployment status
- Rollback option

### 6. Findings (new/enhanced)
- Aggregated findings from all agents
- Filter by agent, severity, type
- Export findings
- Mark as resolved

---

## Agent Configuration Schema

```json
{
  "agent_id": "uuid",
  "version": "2.0.0",
  
  "scanners": {
    "gitleaks": {
      "enabled": true,
      "path": "C:\\Tools\\gitleaks.exe",
      "extra_args": ["--no-git"]
    },
    "trufflehog": {
      "enabled": true,
      "path": "C:\\Tools\\trufflehog.exe",
      "extra_args": []
    },
    "custom": {
      "enabled": true,
      "signatures_url": "http://manager:8443/api/v1/signatures"
    }
  },
  
  "resource_limits": {
    "max_cpu_percent": 50,
    "max_memory_mb": 500,
    "max_concurrent_scans": 2,
    "io_throttle": true
  },
  
  "watch": {
    "enabled": true,
    "paths": ["C:\\Projects", "D:\\Repos"],
    "debounce_seconds": 5,
    "file_patterns": ["*.py", "*.js", "*.json", "*.env", "*.yml"],
    "exclude_patterns": ["node_modules", ".git", "__pycache__"]
  },
  
  "logging": {
    "level": "INFO",
    "local_retention_days": 7,
    "stream_to_manager": true
  },
  
  "heartbeat_interval": 30,
  "job_poll_interval": 10
}
```

---

## Implementation Priority

### Phase 1: Core (This Session)
1. ✅ Database schema updates
2. ✅ Enterprise agent with 3 scanners + resource limits
3. ✅ Enhanced API endpoints
4. ✅ Basic dashboard updates

### Phase 2: Advanced
1. File watching with watchdog
2. Log streaming (WebSocket)
3. Auto-update mechanism
4. Schedule management UI

### Phase 3: Polish
1. Real-time dashboard updates
2. Findings aggregation view
3. Config templates
4. Bulk operations
