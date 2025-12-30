# Multi-Project/Directory Management

This feature allows you to manage multiple scan directories/projects from the SecretSnipe dashboard.

## Status: 🟡 Code Ready, Not Deployed

The code is implemented but not yet deployed. Follow the deployment steps when ready.

## Features

### 1. Project Manager (`project_manager.py`)
- Add/remove/update scan directories
- Configure scan schedules (manual, hourly, daily, weekly)
- Set priority levels for directories
- Queue scan requests

### 2. Scan Request Processor (`scan_request_processor.py`)
- Background processor for scan queue
- Supports scan types:
  - `full` - All scanners (Custom + TruffleHog + Gitleaks)
  - `incremental` - Only changed files
  - `custom_only` - Only custom signature scanner
  - `trufflehog_only` - Only TruffleHog
  - `gitleaks_only` - Only Gitleaks

### 3. Dashboard UI
- "📂 Projects" button in header
- Project Management modal with:
  - List of configured scan directories
  - Add new directory form
  - Manual scan trigger with scan type selection
  - Pending/running scans display

## Deployment Steps

### Step 1: Run Database Migration
```bash
docker exec -i secretsnipe-postgres psql -U secretsnipe -d secretsnipe < scripts/add_scan_directories.sql
```

### Step 2: Rebuild Visualizer
```bash
docker compose build visualizer --no-cache
```

### Step 3: Restart Visualizer
```bash
docker compose up -d visualizer
```

### Step 4: (Optional) Run Scan Processor as Standalone
```bash
# Process pending scans once
python scan_request_processor.py --once

# Run continuously
python scan_request_processor.py
```

## Database Tables Created

### `scan_directories`
| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| directory_path | TEXT | Absolute path to scan |
| display_name | TEXT | Friendly name |
| schedule | VARCHAR(50) | manual/hourly/daily/weekly |
| priority | INTEGER | Scan priority (1-10) |
| include_patterns | TEXT[] | Glob patterns to include |
| exclude_patterns | TEXT[] | Glob patterns to exclude |
| is_active | BOOLEAN | Whether active for scanning |
| created_at | TIMESTAMP | When added |
| last_scan_at | TIMESTAMP | Last scan time |

### `scan_requests`
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| directory_id | INTEGER | FK to scan_directories |
| scan_type | VARCHAR(50) | full/incremental/custom_only/etc. |
| status | VARCHAR(20) | pending/running/completed/failed/cancelled |
| priority | INTEGER | Request priority |
| files_scanned | INTEGER | Count of files scanned |
| findings_count | INTEGER | Count of findings |
| error_message | TEXT | Error details if failed |
| requested_at | TIMESTAMP | When requested |
| started_at | TIMESTAMP | When started |
| completed_at | TIMESTAMP | When finished |

## Usage After Deployment

1. Click "📂 Projects" button in the header
2. Add directories you want to scan:
   - Enter the absolute path
   - Give it a friendly name
   - Select a schedule (manual = only when you trigger)
   - Set priority (higher = scanned first)
3. Click "⚡ Trigger Scan" to start a scan
4. Select scan type in the confirmation dialog
5. Monitor pending scans in the modal

## Future Enhancements

- [ ] Automatic scheduled scanning (requires cron or background service)
- [ ] Per-project findings view in dashboard
- [ ] Per-project false positive management
- [ ] Per-project Jira ticket creation
- [ ] Project-based statistics and reporting
