# SecretSnipe Agent Quickstart Guide

Get up and running with SecretSnipe agents in 10 minutes.

## Prerequisites

- Docker & Docker Compose (for manager)
- Python 3.9+ (for agents)
- Network connectivity between agents and manager

## Step 1: Deploy the Manager

```bash
cd agent_project

# Create environment file
cat > .env << 'EOF'
DB_PASSWORD=ChangeMeInProduction!
BOOTSTRAP_ENABLED=true
LOG_LEVEL=INFO
EOF

# Start manager infrastructure
docker-compose -f docker-compose.agent.yml up -d

# Wait for services to be healthy (about 30 seconds)
docker-compose -f docker-compose.agent.yml ps
```

Expected output:
```
NAME                        STATUS
secretsnipe-agent-db        Up (healthy)
secretsnipe-agent-redis     Up (healthy)
secretsnipe-agent-manager   Up (healthy)
```

## Step 2: Create an API Key

```bash
# Use the bootstrap endpoint to create initial API key
curl -X POST http://localhost:8443/api/v1/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Initial Admin Key",
    "description": "Created during setup"
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "api_key": "ss_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "name": "Initial Admin Key",
    "expires_at": "2026-06-03T..."
  }
}
```

⚠️ **SAVE THIS API KEY!** It won't be shown again.

## Step 3: Install an Agent

### Linux (Quick Install)

```bash
# On the target host, run:
curl -fsSL https://your-manager-server/scripts/install_agent.sh | sudo bash -s -- \
  --manager-url http://YOUR_MANAGER_IP:8443 \
  --api-key ss_your_api_key_here
```

### Linux (Manual)

```bash
# 1. Install dependencies
sudo apt install python3 python3-pip python3-venv

# 2. Create agent directory
sudo mkdir -p /opt/secretsnipe-agent/{bin,config,logs,venv}

# 3. Create virtual environment
python3 -m venv /opt/secretsnipe-agent/venv
source /opt/secretsnipe-agent/venv/bin/activate
pip install requests psutil

# 4. Copy the agent script (from agent_project/agent/agent_core.py)
# Or download from your manager

# 5. Create config
cat > /opt/secretsnipe-agent/config/agent.env << EOF
SECRETSNIPE_MANAGER_URL=http://YOUR_MANAGER_IP:8443
SECRETSNIPE_API_KEY=ss_your_api_key_here
SECRETSNIPE_SCAN_PATHS=/home,/var/www,/opt
EOF

# 6. Run the agent
export $(cat /opt/secretsnipe-agent/config/agent.env | xargs)
python /opt/secretsnipe-agent/bin/agent_core.py
```

### Windows

```powershell
# Run as Administrator
.\install_agent.ps1 -ManagerUrl "http://YOUR_MANAGER_IP:8443" -ApiKey "ss_your_api_key"
```

## Step 4: Verify Agent Registration

```bash
# Check registered agents
curl -H "X-API-Key: ss_your_api_key" \
  http://localhost:8443/api/v1/agents
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "agent_id": "abc123...",
      "hostname": "server1",
      "status": "online",
      "capabilities": ["custom", "trufflehog", "gitleaks"]
    }
  ]
}
```

## Step 5: Create a Scan Job

```bash
# Create a scan job for the agent
curl -X POST http://localhost:8443/api/v1/jobs \
  -H "X-API-Key: ss_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "abc123...",
    "scan_paths": ["/home/user/projects", "/var/www"],
    "scanners": ["custom", "trufflehog"],
    "priority": 5
  }'
```

## Step 6: Monitor Results

### Via API

```bash
# Check job status
curl -H "X-API-Key: ss_your_api_key" \
  http://localhost:8443/api/v1/jobs

# Get statistics
curl -H "X-API-Key: ss_your_api_key" \
  http://localhost:8443/api/v1/stats
```

### Via Dashboard (Optional)

```bash
# Start the dashboard
docker-compose -f docker-compose.agent.yml --profile dashboard up -d

# Open in browser
open http://localhost:8052
```

## Common Operations

### List all agents
```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8443/api/v1/agents
```

### Create API key for another agent
```bash
curl -X POST http://localhost:8443/api/v1/keys \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Production Agent", "expires_days": 365}'
```

### Delete an agent
```bash
curl -X DELETE http://localhost:8443/api/v1/agents/AGENT_ID \
  -H "X-API-Key: $API_KEY"
```

### Filter jobs by status
```bash
curl -H "X-API-Key: $API_KEY" \
  "http://localhost:8443/api/v1/jobs?status=completed"
```

## Troubleshooting

### Agent won't connect
```bash
# Check agent logs
journalctl -u secretsnipe-agent -f

# Test connectivity
curl -v http://MANAGER_IP:8443/api/v1/health
```

### Jobs stuck in pending
```bash
# Ensure agent is online
curl -H "X-API-Key: $API_KEY" http://localhost:8443/api/v1/agents

# Check agent is polling
journalctl -u secretsnipe-agent | grep "poll"
```

### Database issues
```bash
# Check database connection
docker-compose -f docker-compose.agent.yml logs agent-db

# Reset database
docker-compose -f docker-compose.agent.yml down -v
docker-compose -f docker-compose.agent.yml up -d
```

## Next Steps

1. **Security**: Enable HTTPS with certificates
2. **Scale**: Deploy agents to more hosts
3. **Integrate**: Connect to main SecretSnipe dashboard
4. **Automate**: Set up scheduled scanning jobs
5. **Monitor**: Configure alerting for critical findings

See [AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) for detailed documentation.
