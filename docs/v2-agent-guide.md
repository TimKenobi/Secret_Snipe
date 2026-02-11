# SecretSnipe V2 Agent-Based Scanner - Complete Guide

## Overview

SecretSnipe V2 introduces a distributed agent-based architecture for scanning secrets across your enterprise infrastructure. Unlike V1 which runs scans locally on the server, V2 deploys lightweight agents to Windows/Linux machines that scan local paths and report findings back to the central dashboard.

## Architecture

### Components

| Component | Container | Port | Purpose |
|-----------|-----------|------|---------|
| V2 Dashboard | `secretsnipe-visualizer-v2` | 8052 | Web UI for V2 agent management |
| Agent Manager | `secretsnipe-agent-manager` | 8443 | API for agent communication |
| Agent DB | `secretsnipe-agent-db` | 5433 | PostgreSQL for agent data |
| Agent Redis | `secretsnipe-agent-redis` | 6380 | Caching and pub/sub |

### Database Separation

- **V1 Database** (`secretsnipe` on port 5432): Original scanner findings
- **V2 Database** (`secretsnipe_v2` on port 5432): V2 dashboard settings (future use)
- **Agent Database** (`secretsnipe_agents` on port 5433): Agents, jobs, findings, address book

### File Separation

| File | Version | Purpose |
|------|---------|---------|
| `unified_visualizer_pg.py` | V1 | Original dashboard |
| `unified_visualizer_v2.py` | V2 | Agent-mode dashboard |
| `agent_administration.py` | V2 | Admin panel with agent management |
| `agent_project/secretsnipe_agent.py` | V2 | Agent deployed to endpoints |

---

## Installation

### Server Setup

1. Start the containers:
```bash
cd /home/gsrpdadmin/Secret_Snipe
docker compose up -d visualizer-v2 agent-manager agent-db agent-redis
```

2. Access the V2 dashboard at: `http://your-server:8052`
   - Default credentials: `admin` / `secretsnipe`
   - Configure in docker-compose.yml via `DASH_USERNAME` / `DASH_PASSWORD`

### Agent Installation (Windows)

#### Basic Installation

```powershell
# Run as Administrator
.\Install-SecretSnipeAgent.ps1 `
    -ManagerUrl "http://your-server:8443" `
    -ApiKey "your-api-key-from-dashboard"
```

#### Installation with Service Account (Required for Network Shares)

```powershell
# For scanning network shares (CIFS/SMB), use a domain service account
$password = Read-Host "Enter service account password" -AsSecureString

.\Install-SecretSnipeAgent.ps1 `
    -ManagerUrl "http://your-server:8443" `
    -ApiKey "your-api-key-from-dashboard" `
    -ServiceAccount "DOMAIN\svc-secretsnipe" `
    -ServicePassword $password
```

#### Installation Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-ManagerUrl` | Yes | - | URL to agent manager API |
| `-ApiKey` | Yes | - | API key from dashboard |
| `-InstallPath` | No | `C:\Program Files\SecretSnipe` | Installation directory |
| `-ServiceAccount` | No | `LocalSystem` | Service account (domain account for network shares) |
| `-ServicePassword` | No | - | Password for service account |
| `-ScanPaths` | No | `[]` | Paths to add to default scans |
| `-DisableGitleaks` | No | `false` | Skip Gitleaks scanner |
| `-DisableTrufflehog` | No | `false` | Skip TruffleHog scanner |
| `-MaxCpuPercent` | No | `50` | CPU limit for agent |
| `-MaxMemoryMB` | No | `512` | Memory limit for agent |

#### Verification

```powershell
# Check service status
Get-Service SecretSnipeAgent

# View logs
Get-Content "C:\Program Files\SecretSnipe\logs\agent.log" -Tail 50
```

### Agent Uninstallation

```powershell
# From dashboard: Select agent → "Uninstall" button
# Or locally:
.\Install-SecretSnipeAgent.ps1 -Uninstall
```

---

## Scanning Network Shares (CIFS/SMB)

The key challenge with network shares is that the Windows service runs as `LocalSystem` by default, which has no network identity.

### Option 1: Service Account (Recommended)

Install the agent with a domain service account that has read access to the shares:

```powershell
$password = ConvertTo-SecureString "YourPassword" -AsPlainText -Force
.\Install-SecretSnipeAgent.ps1 `
    -ManagerUrl "http://your-server:8443" `
    -ApiKey "your-api-key" `
    -ServiceAccount "STAHLS\svc-secretsnipe" `
    -ServicePassword $password
```

Requirements for the service account:
- Read access to the network shares
- "Log on as a service" right
- Member of appropriate AD groups

Then create a scan job targeting the UNC path:
```
\\shsna1cifs1.stahls.net\open
```

### Option 2: Pre-Authenticated User Session

If the share is accessible when logged in as a user:

1. Map the drive in a persistent session:
```powershell
net use Z: \\shsna1cifs1.stahls.net\open /persistent:yes
```

2. Create a scan job targeting `Z:\`

### Option 3: Credential Storage (In Job)

Jobs can include share credentials (stored encrypted):

1. In the job creation form, add the UNC path
2. Provide credentials in the "Share Credentials" section
3. The agent will mount the share temporarily during the scan

> **Security Note**: Credentials are sent encrypted but should only be used when service account isn't feasible.

---

## Dashboard Usage

### Accessing the Dashboard

- URL: `http://your-server:8052`
- Login: `admin` / `secretsnipe` (or as configured)

### Navigation Tabs

| Tab | Purpose |
|-----|---------|
| **Overview** | Summary stats for agent-mode findings |
| **Agents** | List and manage registered agents |
| **Jobs** | Create and monitor scan jobs |
| **Findings** | Browse agent-reported secrets |
| **Admin** | Agent management, API keys, address book |

### Creating a Scan Job

1. Go to **Admin** tab → **Jobs** section
2. Select the target agent from dropdown
3. Enter scan paths (one per line):
   ```
   C:\Projects
   D:\Code
   \\server\share
   ```
4. For scheduled scans, check "Continuous Scan" and select interval
5. Click "Create Job"

### Managing Agents

In the **Admin** tab:

| Button | Action |
|--------|--------|
| **Restart** | Restart agent service remotely |
| **Update** | Push latest agent version |
| **Repair** | Reinstall scanner dependencies |
| **Status** | Request detailed status report |
| **Uninstall** | Remove agent completely (wipes config) |
| **Remove** | Remove from database only |

### Address Book / Owner Assignment

The **Contacts** tab allows you to:

1. **Add contacts** - Create entries in the address book
2. **Path ownership rules** - Auto-assign owners based on file paths
3. **Bulk assignment** - Assign owners to multiple findings at once

Example path ownership rule:
```
Path Pattern: \\shsna1cifs1.stahls.net\HR\*
Owner: John Smith (john.smith@company.com)
```

---

## API Keys

Generate API keys for agent registration:

1. Go to **Admin** → **API Keys**
2. Click "Generate New Key"
3. Set name and expiration
4. Copy the key (shown once)

Permissions:
- **agent:register** - Allow new agents to register
- **agent:heartbeat** - Allow agents to send heartbeats
- **findings:submit** - Allow agents to submit scan results

---

## Troubleshooting

### Agent Not Connecting

1. Check firewall allows outbound 8443
2. Verify API key is valid
3. Check agent logs: `C:\Program Files\SecretSnipe\logs\agent.log`

### Network Share Access Denied

1. Verify service account has share access:
   ```powershell
   runas /user:DOMAIN\svc-secretsnipe "dir \\server\share"
   ```
2. Check service is running as correct account:
   ```powershell
   Get-WmiObject Win32_Service | Where Name -eq SecretSnipeAgent | Select StartName
   ```

### No Findings from Scanners

1. Check scanner installation:
   ```powershell
   Test-Path "C:\Program Files\SecretSnipe\scanners\gitleaks.exe"
   Test-Path "C:\Program Files\SecretSnipe\scanners\trufflehog.exe"
   ```
2. Run scanner manually:
   ```powershell
   & "C:\Program Files\SecretSnipe\scanners\gitleaks.exe" detect --source C:\test -v
   ```

### Login Not Working

- Default credentials: `admin` / `secretsnipe`
- Set custom via `DASH_USERNAME` / `DASH_PASSWORD` environment variables
- Restart container after changing: `docker compose up -d visualizer-v2`

### Agent Shows Offline

- Agents heartbeat every 30 seconds
- If offline > 2 minutes, investigate:
  1. Service running? `Get-Service SecretSnipeAgent`
  2. Network connectivity? `Test-NetConnection your-server -Port 8443`
  3. API key expired?

---

## Best Practices

1. **Service Accounts**: Always use domain service accounts for agents that need network share access

2. **API Key Rotation**: Generate new API keys periodically and revoke old ones

3. **Path Ownership**: Set up path ownership rules to automatically assign finding owners

4. **Scheduled Scans**: Use continuous scans for critical paths with appropriate intervals

5. **Resource Limits**: Set appropriate CPU/memory limits based on endpoint capacity

---

## Configuration Reference

### Agent Config File

Location: `C:\Program Files\SecretSnipe\config\agent_config.json`

```json
{
    "manager_url": "http://10.150.110.24:8443",
    "api_key": "your-api-key",
    "machine_fingerprint": "auto-generated",
    "heartbeat_interval": 30,
    "poll_interval": 10,
    "scanners": {
        "gitleaks": {"enabled": true},
        "trufflehog": {"enabled": true},
        "custom": {"enabled": true}
    },
    "resource_limits": {
        "max_cpu_percent": 50,
        "max_memory_mb": 512
    },
    "additional_paths": []
}
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `SECRETSNIPE_MANAGER_URL` | Override manager URL |
| `SECRETSNIPE_API_KEY` | Override API key |
| `SECRETSNIPE_INSTALL_PATH` | Override install path |

---

## Version History

- **2.0.4** - Added uninstall command, address book, CIFS support
- **2.0.3** - Continuous scans, path ownership
- **2.0.2** - Fixed version reporting, enhanced drive enumeration
- **2.0.1** - Initial agent-based scanner release
