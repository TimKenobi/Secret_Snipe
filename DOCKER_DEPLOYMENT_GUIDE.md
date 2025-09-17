# SecretSnipe Docker Deployment Options

## Option 1: Minimal Self-Contained Deployment (Recommended)

For a completely self-contained deployment with no external dependencies:

```bash
# Start only core services (scanner, visualizer, database, redis)
docker-compose up postgres redis scanner visualizer
```

This provides:
- ✅ Complete secret scanning functionality
- ✅ Web dashboard for results visualization
- ✅ PostgreSQL database for persistent storage
- ✅ Redis caching for performance
- ✅ All external scanners (Trufflehog, Gitleaks) built into container
- ❌ No webhook notifications
- ❌ No Teams integration

## Option 2: Full Deployment with Optional External Services

For complete functionality including external integrations:

```bash
# Start all services including webhooks and monitoring
docker-compose --profile monitoring up
```

This adds:
- ✅ Everything from minimal deployment
- ✅ Webhook notifications to external endpoints
- ✅ Teams integration for weekly reports
- ✅ Continuous monitoring with file watching

## Configuration for External Services

### Environment Variables (Optional)

Create a `.env` file for external integrations:

```env
# Database (auto-configured if not specified)
POSTGRES_PASSWORD=your_secure_password

# Optional: Webhook Configuration
WEBHOOK_URL=https://your-webhook-endpoint.com/alerts
WEBHOOK_ENABLED=true

# Optional: Teams Integration
TEAMS_WEBHOOK_URL=https://your-teams-webhook-url

# Optional: Monitoring
MONITOR_PATH=/path/to/watch
```

### Completely Offline Operation

For air-gapped or completely offline environments:

1. **Build containers offline**: All tools are downloaded during build
2. **No internet required at runtime**: Everything is self-contained
3. **Optional features can be disabled**: Webhooks and Teams integration are optional

## Container Architecture

```
┌─────────────────────────────────────────┐
│           Docker Network               │
├─────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐ │
│  │PostgreSQL│  │  Redis  │  │ Scanner │ │
│  │         │  │         │  │         │ │
│  │         │  │         │  │ Custom  │ │
│  │         │  │         │  │Trufflehog│ │
│  │         │  │         │  │ Gitleaks│ │
│  └─────────┘  └─────────┘  └─────────┘ │
│                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐ │
│  │Dashboard│  │Webhook  │  │Monitor  │ │
│  │(Dash)   │  │(Optional)│  │(Optional)│ │
│  └─────────┘  └─────────┘  └─────────┘ │
└─────────────────────────────────────────┘
```

## Security Features

- **Non-root containers**: All processes run as unprivileged users
- **Read-only filesystems**: Container filesystems are read-only where possible
- **Resource limits**: Memory and CPU limits prevent resource exhaustion
- **Network isolation**: Services communicate only through private Docker network
- **No external internet required**: Runtime operation is completely offline