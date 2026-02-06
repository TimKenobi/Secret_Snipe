# SecretSnipe Agent Architecture Documentation

## Overview

The SecretSnipe Agent Architecture enables distributed secret scanning across multiple hosts. Instead of scanning network shares via SMB (which has security and performance limitations), lightweight agents are deployed to target hosts where they perform local scanning and report findings back to a central manager.

## Architecture Diagram

```
                                    ┌──────────────────────────────────────────┐
                                    │         Agent Manager (Central)           │
                                    │  ┌─────────────────────────────────────┐  │
                                    │  │        FastAPI Server (8443)        │  │
                                    │  │  • Agent Registration               │  │
                                    │  │  • Heartbeat Processing             │  │
                                    │  │  • Job Distribution                 │  │
                                    │  │  • Findings Collection              │  │
                                    │  └─────────────────────────────────────┘  │
                                    │  ┌─────────────────────────────────────┐  │
                                    │  │      Dashboard (8051)               │  │
                                    │  │  • Agent Monitoring                 │  │
                                    │  │  • Job Management                   │  │
                                    │  │  • API Key Management               │  │
                                    │  └─────────────────────────────────────┘  │
                                    │  ┌─────────────────────────────────────┐  │
                                    │  │   PostgreSQL  │    Redis            │  │
                                    │  │   (5433)      │    (6380)           │  │
                                    │  └─────────────────────────────────────┘  │
                                    └──────────────────────────────────────────┘
                                                        │
                                                        │ HTTPS (API Key Auth)
                    ┌───────────────────────────────────┼───────────────────────────────────┐
                    │                                   │                                   │
                    ▼                                   ▼                                   ▼
        ┌─────────────────────┐           ┌─────────────────────┐           ┌─────────────────────┐
        │   Linux Agent       │           │   Windows Agent     │           │   Container Agent   │
        │   (Server A)        │           │   (Workstation B)   │           │   (Docker Host)     │
        │                     │           │                     │           │                     │
        │  • Custom Scanner   │           │  • Custom Scanner   │           │  • Custom Scanner   │
        │  • TruffleHog       │           │  • Gitleaks         │           │  • TruffleHog       │
        │  • Gitleaks         │           │                     │           │  • Gitleaks         │
        │                     │           │                     │           │                     │
        │  Scans:             │           │  Scans:             │           │  Scans:             │
        │  /home/users/       │           │  C:\Projects\       │           │  /var/app/          │
        │  /var/www/          │           │  D:\Development\    │           │  /opt/services/     │
        └─────────────────────┘           └─────────────────────┘           └─────────────────────┘
```

## Components

### 1. Agent Manager API (`agent_api.py`)

The central FastAPI server that manages all agents. Runs on port 8443.

**Key Features:**
- Agent registration and lifecycle management
- API key authentication with SHA256 hashing
- Job creation and distribution
- Findings collection and storage
- Real-time health monitoring

**API Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/agents` | GET | List all agents |
| `/api/v1/agents/register` | POST | Register new agent |
| `/api/v1/agents/heartbeat` | POST | Receive heartbeat |
| `/api/v1/agents/{id}` | GET/DELETE | Get or delete agent |
| `/api/v1/jobs` | GET/POST | List or create jobs |
| `/api/v1/jobs/poll` | GET | Poll for pending job |
| `/api/v1/jobs/status` | POST | Update job status |
| `/api/v1/findings/submit` | POST | Submit findings |
| `/api/v1/keys` | GET/POST | Manage API keys |
| `/api/v1/keys/{id}` | DELETE | Revoke API key |
| `/api/v1/stats` | GET | Get statistics |
| `/api/v1/bootstrap` | POST | Create initial API key |

### 2. Agent Core (`agent_core.py`)

The lightweight Python agent that runs on target hosts.

**Features:**
- Automatic registration with manager
- Heartbeat every 30 seconds (configurable)
- Job polling every 10 seconds (configurable)
- Multi-scanner support:
  - Custom regex patterns (built-in)
  - TruffleHog integration
  - Gitleaks integration
- Batch findings submission
- Resource-aware (monitors CPU/memory)

**Built-in Signature Patterns:**
- AWS Access Key ID
- AWS Secret Access Key
- GitHub Tokens (ghp, gho, ghu, ghs, ghr)
- Generic API Keys
- Generic Secrets/Passwords
- Private Key Headers
- Slack Tokens
- Google API Keys
- JWT Tokens

### 3. Agent Dashboard (`agent_dashboard.py`)

A Dash-based web UI for managing agents.

**Features:**
- Real-time agent status monitoring
- Statistics cards (total agents, online, scanning, pending jobs)
- Agent list with status indicators
- Job management (create, view, filter)
- API key management (create, revoke)
- Auto-refresh every 30 seconds

### 4. Database Schema

**Tables:**

```sql
-- API Keys for authentication
agent_api_keys (
    id, key_hash, key_prefix, name, description,
    created_at, expires_at, last_used_at, is_active
)

-- Registered agents
agents (
    id, agent_id, hostname, ip_address, os_type, os_version,
    agent_version, capabilities, scan_paths, status,
    registered_at, last_heartbeat, metadata
)

-- Heartbeat history
agent_heartbeats (
    id, agent_id, status, cpu_percent, memory_percent,
    disk_percent, active_scans, uptime_seconds, recorded_at
)

-- Scan jobs
agent_jobs (
    id, job_id, agent_id, job_type, status, priority,
    scan_paths, scanners, config, created_at, assigned_at,
    started_at, completed_at, files_scanned, findings_count
)

-- Detected secrets
agent_findings (
    id, finding_id, job_id, agent_id, secret_type,
    secret_value, file_path, line_number, scanner,
    severity, status, found_at, hostname
)
```

## Deployment

### Option 1: Docker Deployment (Recommended)

```bash
cd agent_project

# Create .env file
cat > .env << EOF
DB_PASSWORD=your_secure_password
BOOTSTRAP_TOKEN=your_bootstrap_token
DASHBOARD_API_KEY=your_dashboard_key
EOF

# Start the stack
docker-compose -f docker-compose.agent.yml up -d

# With dashboard
docker-compose -f docker-compose.agent.yml --profile dashboard up -d
```

### Option 2: Manual Deployment

```bash
# Install dependencies
pip install -r manager/requirements.txt

# Set environment variables
export DATABASE_URL=postgresql://user:pass@localhost:5432/secretsnipe_agents
export BOOTSTRAP_ENABLED=true

# Run the API server
uvicorn manager.agent_api:app --host 0.0.0.0 --port 8443

# Run dashboard (optional)
python manager/agent_dashboard.py
```

## Agent Installation

### Linux (Automated)

```bash
curl -fsSL https://your-server/install_agent.sh | sudo bash -s -- \
    --manager-url https://manager.example.com:8443 \
    --api-key YOUR_API_KEY
```

### Linux (Manual)

```bash
# Create directories
sudo mkdir -p /opt/secretsnipe-agent/{bin,config,logs}

# Create virtual environment
python3 -m venv /opt/secretsnipe-agent/venv
source /opt/secretsnipe-agent/venv/bin/activate

# Install dependencies
pip install requests psutil pyyaml

# Copy agent_core.py to /opt/secretsnipe-agent/bin/

# Create config
cat > /opt/secretsnipe-agent/config/agent.env << EOF
SECRETSNIPE_MANAGER_URL=https://manager:8443
SECRETSNIPE_API_KEY=your_key
SECRETSNIPE_SCAN_PATHS=/home,/var/www
EOF

# Create systemd service
sudo systemctl enable secretsnipe-agent
sudo systemctl start secretsnipe-agent
```

### Windows

```powershell
.\install_agent.ps1 -ManagerUrl "https://manager:8443" -ApiKey "your_key"
```

## Security Considerations

### API Key Authentication
- Keys are hashed with SHA256 before storage
- Only the key prefix is stored for identification
- Keys can have expiration dates
- Keys can be revoked immediately

### Network Security
- All communication over HTTPS (recommended)
- Single port (8443) required for firewall rules
- Agents initiate all connections (no inbound required on agents)

### Agent Isolation
- Agents run with limited permissions
- Scan paths are configurable per agent
- Resource limits can be enforced via systemd/Docker

### Secret Handling
- Secrets are partially redacted in storage
- Full secrets only shown to authorized users
- Findings can be marked as false positives

## Configuration Reference

### Manager Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | required | PostgreSQL connection string |
| `REDIS_URL` | optional | Redis for caching |
| `API_HOST` | 0.0.0.0 | API bind address |
| `API_PORT` | 8443 | API port |
| `BOOTSTRAP_ENABLED` | true | Allow initial key creation |
| `BOOTSTRAP_TOKEN` | empty | Token for bootstrap (optional) |
| `SSL_ENABLED` | false | Enable HTTPS |
| `SSL_CERT_FILE` | | Path to SSL certificate |
| `SSL_KEY_FILE` | | Path to SSL key |
| `LOG_LEVEL` | INFO | Logging level |
| `AGENT_TIMEOUT_SECONDS` | 120 | Mark agent offline after |
| `JOB_TIMEOUT_SECONDS` | 3600 | Max job runtime |

### Agent Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRETSNIPE_MANAGER_URL` | required | Manager API URL |
| `SECRETSNIPE_API_KEY` | required | API key for auth |
| `SECRETSNIPE_AGENT_ID` | auto | Persistent agent ID |
| `SECRETSNIPE_SCAN_PATHS` | empty | Default paths to scan |
| `SECRETSNIPE_HEARTBEAT_INTERVAL` | 30 | Heartbeat frequency (sec) |
| `SECRETSNIPE_POLL_INTERVAL` | 10 | Job poll frequency (sec) |
| `SECRETSNIPE_LOG_LEVEL` | INFO | Logging level |
| `SECRETSNIPE_MAX_FILE_SIZE` | 10MB | Skip files larger than |
| `SECRETSNIPE_GITLEAKS_PATH` | gitleaks | Path to gitleaks binary |

## Troubleshooting

### Agent Not Registering
1. Check network connectivity to manager
2. Verify API key is valid and not expired
3. Check agent logs: `journalctl -u secretsnipe-agent -f`
4. Ensure bootstrap is enabled or key exists

### Agent Shows Offline
1. Check heartbeat thread is running
2. Verify no firewall blocking outbound HTTPS
3. Check manager logs for heartbeat errors
4. Increase AGENT_TIMEOUT_SECONDS if network is slow

### Jobs Not Running
1. Verify agent status is "online"
2. Check scan paths exist on agent
3. Review job status in dashboard
4. Check agent logs for errors

### High Memory Usage
1. Reduce MAX_FILE_SIZE
2. Limit scan paths to specific directories
3. Exclude large binary directories
4. Add patterns to SKIP_DIRS

## Extending the Agent

### Adding Custom Scanners

```python
# In agent_core.py, add new scanner method:

def _scan_path_custom_scanner(self, path: Path) -> list:
    """Your custom scanner"""
    findings = []
    # Your scanning logic
    return findings

# Add to _execute_job():
if "custom_scanner" in scanners:
    findings = self._scan_path_custom_scanner(path)
    all_findings.extend(findings)
```

### Adding New Signatures

```python
# Add to SIGNATURES list:
{"name": "MySecret", "pattern": r"my_secret_[a-z0-9]+", "severity": "high"},
```

## Integration with Main SecretSnipe

The agent findings are stored in a separate database but can be integrated:

1. **Database Level**: Create views joining agent_findings with main findings
2. **API Level**: Create proxy endpoints in main dashboard
3. **Export Level**: Export agent findings to CSV/JSON for import

## Roadmap

- [ ] mTLS authentication (client certificates)
- [ ] Agent groups and targeting
- [ ] Scheduled recurring scans
- [ ] Custom signature sets per agent
- [ ] Agent auto-update mechanism
- [ ] Integration with main SecretSnipe dashboard
- [ ] SIEM integration (Splunk, Elastic)
- [ ] Alerting on critical findings
