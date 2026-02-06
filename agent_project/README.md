# SecretSnipe Agent Project

**Distributed Secret Scanning with Lightweight Agents**

This is the agent-based architecture for SecretSnipe, enabling secret scanning across multiple hosts without the security and performance overhead of SMB/network share scanning.

## 🏗️ Architecture

```
┌────────────────────┐     HTTPS/API Key     ┌─────────────────────────┐
│   Agent Manager    │◄───────────────────────│    Remote Agents        │
│   (Central Server) │                        │    (Linux/Windows)      │
│                    │                        │                         │
│  • FastAPI Server  │     Heartbeats        │  • Custom Scanner       │
│  • PostgreSQL DB   │     Job Polling       │  • TruffleHog           │
│  • Dash Dashboard  │     Findings Submit   │  • Gitleaks             │
└────────────────────┘                        └─────────────────────────┘
```

## 📁 Project Structure

```
agent_project/
├── shared/                  # Shared models and config
│   ├── models.py           # Data models (Agent, Job, Finding, etc.)
│   └── config.py           # Configuration classes
├── agent/                   # Agent (runs on remote hosts)
│   ├── agent_core.py       # Main agent with scanners
│   └── requirements.txt    # Agent dependencies
├── manager/                 # Manager (central server)
│   ├── agent_api.py        # FastAPI server
│   ├── agent_dashboard.py  # Dash web UI
│   └── requirements.txt    # Manager dependencies
├── scripts/                 # Deployment scripts
│   ├── init_agent_db.sql   # Database schema
│   ├── install_agent.sh    # Linux installer
│   └── install_agent.ps1   # Windows installer
├── docs/                    # Documentation
│   └── AGENT_ARCHITECTURE.md
├── docker-compose.agent.yml # Docker deployment
├── Dockerfile.manager       # Manager container
├── Dockerfile.dashboard     # Dashboard container
├── QUICKSTART.md           # Quick start guide
└── .env.example            # Environment template
```

## 🚀 Quick Start

### 1. Deploy Manager (Docker)

```bash
# Copy environment template
cp .env.example .env

# Edit .env with secure password
nano .env

# Start services
docker-compose -f docker-compose.agent.yml up -d
```

### 2. Create Initial API Key

```bash
curl -X POST http://localhost:8443/api/v1/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"name": "Admin Key"}'
```

Save the returned API key!

### 3. Install Agent

**Linux:**
```bash
curl -fsSL https://your-server/install_agent.sh | sudo bash -s -- \
  --manager-url http://manager:8443 \
  --api-key YOUR_API_KEY
```

**Windows:**
```powershell
.\install_agent.ps1 -ManagerUrl "http://manager:8443" -ApiKey "YOUR_KEY"
```

### 4. Create Scan Job

```bash
curl -X POST http://localhost:8443/api/v1/jobs \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"scan_paths": ["/home", "/var/www"], "scanners": ["custom"]}'
```

## 🔐 Security Features

- **API Key Authentication**: SHA256 hashed, expiring keys
- **Bootstrap Protection**: Optional token requirement
- **HTTPS Support**: TLS encryption for all communication
- **Agent Isolation**: Limited permissions, configurable scan paths
- **Secret Redaction**: Partial values stored to protect secrets

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/agents` | GET | List agents |
| `/api/v1/agents/register` | POST | Register agent |
| `/api/v1/agents/heartbeat` | POST | Agent heartbeat |
| `/api/v1/jobs` | GET/POST | List/create jobs |
| `/api/v1/jobs/poll` | GET | Agent polls for jobs |
| `/api/v1/findings/submit` | POST | Submit findings |
| `/api/v1/keys` | GET/POST | Manage API keys |
| `/api/v1/stats` | GET | Statistics |
| `/api/v1/bootstrap` | POST | Initial setup |

## 🛠️ Configuration

### Manager Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `BOOTSTRAP_ENABLED` | Allow initial key creation |
| `SSL_ENABLED` | Enable HTTPS |
| `LOG_LEVEL` | Logging verbosity |

### Agent Environment Variables

| Variable | Description |
|----------|-------------|
| `SECRETSNIPE_MANAGER_URL` | Manager API URL |
| `SECRETSNIPE_API_KEY` | Authentication key |
| `SECRETSNIPE_SCAN_PATHS` | Default paths to scan |
| `SECRETSNIPE_HEARTBEAT_INTERVAL` | Heartbeat frequency |

## 📋 Supported Scanners

1. **Custom Scanner** - Built-in regex patterns for common secrets
2. **TruffleHog** - Deep secret detection with entropy analysis
3. **Gitleaks** - Fast secret scanning with extensive rules

## 🔗 Integration

This project is **separate from the main SecretSnipe deployment** to avoid disrupting production. It uses:
- Different database (port 5433)
- Different Redis (port 6380)
- Different API port (8443)

Once stable, findings can be integrated via:
- Database views/joins
- API proxying
- Export/import

## 📖 Documentation

- [Quick Start Guide](QUICKSTART.md)
- [Architecture Details](docs/AGENT_ARCHITECTURE.md)

## 🗺️ Roadmap

- [ ] mTLS client certificate auth
- [ ] Agent groups and targeting
- [ ] Scheduled recurring scans
- [ ] Custom signatures per agent
- [ ] Auto-update mechanism
- [ ] Main dashboard integration
- [ ] SIEM integration
- [ ] Critical finding alerts

## License

Same as main SecretSnipe project.
