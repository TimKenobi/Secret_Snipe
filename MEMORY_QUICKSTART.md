# Quick Start: Reducing Memory Usage

## Immediate Actions

### 1. For Docker Users
Add these to your `.env` file or export before running:

```bash
# Low Memory Mode (< 2GB RAM)
SCANNER_MEMORY_LIMIT_MB=256
TRUFFLEHOG_CONCURRENCY=1
GITLEAKS_MAX_FILE_SIZE_MB=5
MAX_FINDINGS_PER_SCAN=5000
```

### 2. For Docker Compose
```bash
# Use the optimized settings
docker-compose down
docker-compose up -d
```

### 3. For Direct Python Execution
```bash
# Source the environment file
source .env.memory-optimization

# Or export individually
export SCANNER_MEMORY_LIMIT_MB=512
export TRUFFLEHOG_CONCURRENCY=2
export GITLEAKS_MAX_FILE_SIZE_MB=10

# Run scanner
python run_secret_scanner_pg.py /path/to/scan
```

## What Changed?

1. **TruffleHog now runs with**:
   - Concurrency limited to 2 workers (down from 10+)
   - Memory cap at 512MB per process
   - Findings processed incrementally (not all at once)
   - Max 10,000 findings per scan

2. **Gitleaks now runs with**:
   - Skip files larger than 10MB
   - Memory cap at 512MB per process
   - Max depth limit of 10 directories

3. **Docker containers**:
   - Scanner reduced from 4GB to 2GB limit
   - Minimal deployment uses 768MB limit

## Settings Cheat Sheet

| Environment | Memory Limit | Concurrency | Max File Size | Notes |
|------------|--------------|-------------|---------------|-------|
| **Low** (< 2GB) | 256MB | 1 | 5MB | Slow but stable |
| **Balanced** (4-8GB) | 512MB | 2 | 10MB | **Recommended** |
| **High** (16GB+) | 2048MB | 4 | 50MB | Fast but hungry |

## Verify It's Working

Check logs for these messages:
```
INFO: Starting trufflehog scanner...
INFO: Memory limit: 512MB, Concurrency: 2
INFO: trufflehog completed: {'success': True, 'findings': 45}
```

If you see memory warnings:
```
WARNING: TruffleHog hit memory limit - consider reducing TRUFFLEHOG_CONCURRENCY
```
Then lower your settings further.

## Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| Scanner still uses too much memory | Lower `SCANNER_MEMORY_LIMIT_MB` to 256 |
| Scanner gets killed/OOM | Reduce `TRUFFLEHOG_CONCURRENCY` to 1 |
| Scans too slow | Increase concurrency if memory allows |
| Missing findings | Increase `MAX_FINDINGS_PER_SCAN` |

## More Information
See [MEMORY_OPTIMIZATION.md](MEMORY_OPTIMIZATION.md) for complete documentation.
