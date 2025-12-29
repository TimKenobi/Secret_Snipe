# Memory Optimization Guide for SecretSnipe

## Overview
This document describes the memory throttling mechanisms implemented to reduce resource consumption from TruffleHog and Gitleaks scanners.

## Problem Statement
TruffleHog and Gitleaks can consume excessive memory when:
- Scanning large directories with deep nesting
- Processing many large files simultaneously
- Loading all findings into memory at once
- Running with high concurrency/parallelism

## Implemented Solutions

### 1. TruffleHog Memory Throttling

#### Configuration Parameters
| Parameter | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| Concurrency | `TRUFFLEHOG_CONCURRENCY` | 2 | Maximum parallel workers |
| Max Depth | `TRUFFLEHOG_MAX_DEPTH` | 5 | Directory traversal depth limit |
| Memory Limit | `SCANNER_MEMORY_LIMIT_MB` | 512 MB | Process memory cap |
| Max Findings | `MAX_FINDINGS_PER_SCAN` | 10000 | Maximum findings to process |

#### How It Works
- **Reduced Concurrency**: Limits parallel file scanning to 2 workers (down from default ~10)
- **Memory Caps**: Uses `resource.setrlimit()` to enforce hard memory limits
- **Incremental Parsing**: Processes findings line-by-line instead of loading all at once
- **Finding Truncation**: Limits secret values to 500 chars, context to 1000 chars
- **Periodic GC**: Forces garbage collection every 100 findings

### 2. Gitleaks Memory Throttling

#### Configuration Parameters
| Parameter | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| Max File Size | `GITLEAKS_MAX_FILE_SIZE_MB` | 10 MB | Skip files larger than this |
| Max Depth | `GITLEAKS_MAX_DEPTH` | 10 | Directory traversal depth limit |
| Memory Limit | `SCANNER_MEMORY_LIMIT_MB` | 512 MB | Process memory cap |

#### How It Works
- **File Size Filtering**: Uses `--max-target-megabytes` to skip large files
- **Memory Caps**: Uses `resource.setrlimit()` to enforce hard memory limits
- **Depth Limiting**: Prevents scanning extremely deep directory structures

### 3. General Optimizations

#### Sequential Execution
Scanners run sequentially (not parallel) to avoid memory spikes:
1. Custom scanner
2. Gitleaks
3. TruffleHog (most memory-intensive last)

#### Forced Garbage Collection
After each scanner completes, Python's garbage collector runs explicitly:
```python
import gc
gc.collect()
```

## Configuration

### Quick Start - Low Memory Mode
For systems with limited memory (< 2GB), use these settings:

**Environment Variables:**
```bash
export SCANNER_MEMORY_LIMIT_MB=256
export TRUFFLEHOG_CONCURRENCY=1
export TRUFFLEHOG_MAX_DEPTH=3
export GITLEAKS_MAX_FILE_SIZE_MB=5
export MAX_FINDINGS_PER_SCAN=5000
```

**config.json:**
```json
{
  "scanner": {
    "threads": 2,
    "memory_limit_mb": 256,
    "trufflehog_concurrency": 1,
    "trufflehog_max_depth": 3,
    "gitleaks_max_file_size_mb": 5,
    "max_findings_per_scan": 5000
  }
}
```

### Balanced Mode (Default)
For systems with 4-8GB memory:
```bash
export SCANNER_MEMORY_LIMIT_MB=512
export TRUFFLEHOG_CONCURRENCY=2
export TRUFFLEHOG_MAX_DEPTH=5
export GITLEAKS_MAX_FILE_SIZE_MB=10
export MAX_FINDINGS_PER_SCAN=10000
```

### High Performance Mode
For systems with 16GB+ memory where speed is priority:
```bash
export SCANNER_MEMORY_LIMIT_MB=2048
export TRUFFLEHOG_CONCURRENCY=4
export TRUFFLEHOG_MAX_DEPTH=10
export GITLEAKS_MAX_FILE_SIZE_MB=50
export MAX_FINDINGS_PER_SCAN=50000
```

## Docker Integration

### docker-compose.yml
Add environment variables to your service:
```yaml
services:
  secretsnipe:
    environment:
      - SCANNER_MEMORY_LIMIT_MB=512
      - TRUFFLEHOG_CONCURRENCY=2
      - GITLEAKS_MAX_FILE_SIZE_MB=10
      - MAX_FINDINGS_PER_SCAN=10000
```

### Docker Resource Limits
Also set container-level memory limits:
```yaml
services:
  secretsnipe:
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M
```

## Monitoring Memory Usage

### Check Memory During Scan
```bash
# Monitor process memory
watch -n 1 'ps aux | grep -E "trufflehog|gitleaks" | head -5'

# Docker container stats
docker stats secretsnipe
```

### Log Analysis
Memory warnings appear in logs:
```
WARNING: TruffleHog hit memory limit - consider reducing TRUFFLEHOG_CONCURRENCY
WARNING: Could not set memory limit: [error details]
WARNING: Reached max findings limit (10000), stopping parse
```

## Troubleshooting

### Scanner Gets Killed / OOM
**Symptoms:** Scanner process terminates unexpectedly, "Killed" in logs

**Solutions:**
1. Reduce `SCANNER_MEMORY_LIMIT_MB` to fit within system limits
2. Lower `TRUFFLEHOG_CONCURRENCY` to 1
3. Decrease `MAX_FINDINGS_PER_SCAN`
4. Increase Docker/system memory allocation

### Scans Too Slow
**Symptoms:** Scans take much longer than before

**Solutions:**
1. Increase `TRUFFLEHOG_CONCURRENCY` (if memory allows)
2. Increase `TRUFFLEHOG_MAX_DEPTH` and `GITLEAKS_MAX_DEPTH`
3. Increase `GITLEAKS_MAX_FILE_SIZE_MB`
4. Consider parallel scanner execution (requires code modification)

### Many Findings Skipped
**Symptoms:** "Reached max findings limit" in logs

**Solutions:**
1. Increase `MAX_FINDINGS_PER_SCAN`
2. Use finding filters to focus on critical secrets
3. Run separate scans on subdirectories

### Memory Limit Not Working
**Symptoms:** Process still uses too much memory

**Solutions:**
1. Verify `resource` module is available: `python -c "import resource"`
2. Check system ulimit: `ulimit -v`
3. Use container-level limits instead (Docker memory constraints)
4. Ensure not running as root (root can bypass ulimits)

## Performance vs Memory Trade-offs

| Setting | Memory Impact | Speed Impact | Recommendation |
|---------|---------------|--------------|----------------|
| Lower concurrency | ↓↓ High reduction | ↑ Slower | Use on constrained systems |
| Reduce max depth | ↓ Medium reduction | ↑↑ Much slower | Only if deep dirs cause issues |
| Lower file size limit | ↓ Low reduction | ↓ Faster (fewer files) | Good balance |
| Limit findings | ↓ Medium reduction | → Minimal impact | Safe default |
| Sequential scanners | ↓ Medium reduction | ↑ Slower overall | Already implemented |

## Best Practices

1. **Start Conservative**: Begin with low memory settings and increase gradually
2. **Monitor First Scan**: Watch memory usage during first scan to establish baseline
3. **Tune Per Environment**: Different codebases need different settings
4. **Log Analysis**: Review logs after scans to identify bottlenecks
5. **Container Limits**: Always set Docker memory limits as secondary safeguard
6. **Regular Testing**: Verify settings after codebase size changes

## Advanced: Batch Scanning

For extremely large codebases, consider scanning in batches:

```bash
# Scan subdirectories separately
for dir in /path/to/code/*; do
  python run_secret_scanner_pg.py "$dir" --scanners trufflehog gitleaks
  sleep 5  # Allow memory to clear between scans
done
```

## Related Files
- [run_secret_scanner_pg.py](run_secret_scanner_pg.py) - Scanner orchestrator
- [config.py](config.py) - Configuration classes
- [config.json](config.json) - Default configuration values
- [docker-compose.yml](docker-compose.yml) - Docker configuration

## Changelog

### 2024-12-18
- Initial implementation of memory throttling
- Added TruffleHog concurrency limits
- Added Gitleaks file size filtering
- Implemented incremental parsing
- Added process memory limits via ulimit
- Created configuration parameters
