# SecretSnipe REST API

This document provides comprehensive documentation for the SecretSnipe REST API endpoints.

## 🔗 Base URL

```
http://localhost:8050/api/v1
```

## 🔐 Authentication

All API endpoints require authentication using HTTP Basic Auth:

```bash
curl -u username:password http://localhost:8050/api/v1/projects
```

## 📋 Endpoints

### Projects

#### GET /projects
List all projects with optional filtering.

**Parameters:**
- `limit` (integer, optional): Maximum number of results (default: 50)
- `offset` (integer, optional): Pagination offset (default: 0)
- `status` (string, optional): Filter by status (`active`, `inactive`, `archived`)

**Response:**
```json
{
  "projects": [
    {
      "id": "uuid",
      "name": "my-project",
      "description": "Project description",
      "status": "active",
      "created_at": "2025-01-15T10:00:00Z",
      "updated_at": "2025-01-15T10:00:00Z",
      "total_scans": 42,
      "last_scan": "2025-01-15T09:30:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

#### POST /projects
Create a new project.

**Request Body:**
```json
{
  "name": "new-project",
  "description": "Project description",
  "status": "active"
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "new-project",
  "description": "Project description",
  "status": "active",
  "created_at": "2025-01-15T10:00:00Z"
}
```

#### GET /projects/{project_id}
Get detailed information about a specific project.

**Response:**
```json
{
  "id": "uuid",
  "name": "my-project",
  "description": "Project description",
  "status": "active",
  "created_at": "2025-01-15T10:00:00Z",
  "updated_at": "2025-01-15T10:00:00Z",
  "statistics": {
    "total_findings": 1250,
    "critical_findings": 15,
    "high_findings": 45,
    "medium_findings": 120,
    "low_findings": 1070,
    "last_scan": "2025-01-15T09:30:00Z",
    "total_scans": 42
  }
}
```

### Findings

#### GET /findings
List findings with advanced filtering options.

**Parameters:**
- `project_id` (string, optional): Filter by project
- `severity` (string, optional): Filter by severity (`critical`, `high`, `medium`, `low`)
- `status` (string, optional): Filter by status (`new`, `acknowledged`, `resolved`, `false_positive`)
- `file_path` (string, optional): Filter by file path (partial match)
- `secret_type` (string, optional): Filter by secret type
- `limit` (integer, optional): Maximum results (default: 50)
- `offset` (integer, optional): Pagination offset (default: 0)
- `sort_by` (string, optional): Sort field (`first_seen`, `severity`, `file_path`)
- `sort_order` (string, optional): Sort order (`asc`, `desc`)

**Response:**
```json
{
  "findings": [
    {
      "id": "uuid",
      "project_id": "uuid",
      "scan_session_id": "uuid",
      "file_path": "/path/to/file.py",
      "line_number": 25,
      "secret_type": "AWS API Key",
      "severity": "high",
      "confidence": 0.95,
      "context": "aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'",
      "masked_secret": "AKIAIOSFODNN7*****",
      "status": "new",
      "first_seen": "2025-01-15T09:30:00Z",
      "last_seen": "2025-01-15T09:30:00Z",
      "acknowledged_at": null,
      "acknowledged_by": null,
      "tags": ["aws", "api-key"]
    }
  ],
  "total": 1250,
  "limit": 50,
  "offset": 0,
  "filters_applied": {
    "severity": "high",
    "status": "new"
  }
}
```

#### POST /findings/{finding_id}/acknowledge
Acknowledge a finding.

**Request Body:**
```json
{
  "comment": "Investigated and found to be a test key"
}
```

#### POST /findings/{finding_id}/resolve
Mark a finding as resolved.

**Request Body:**
```json
{
  "comment": "Key has been rotated"
}
```

#### POST /findings/{finding_id}/false-positive
Mark a finding as a false positive.

**Request Body:**
```json
{
  "comment": "This is a test file, not production code"
}
```

### Scans

#### GET /scans
List scan sessions.

**Parameters:**
- `project_id` (string, optional): Filter by project
- `status` (string, optional): Filter by status (`running`, `completed`, `failed`)
- `limit` (integer, optional): Maximum results (default: 50)

**Response:**
```json
{
  "scans": [
    {
      "id": "uuid",
      "project_id": "uuid",
      "status": "completed",
      "start_time": "2025-01-15T09:00:00Z",
      "end_time": "2025-01-15T09:30:00Z",
      "duration_seconds": 1800,
      "files_scanned": 15420,
      "findings_count": 1250,
      "errors_count": 5,
      "scanner_version": "2.1.0",
      "scan_config": {
        "threads": 4,
        "timeout_seconds": 300,
        "max_file_size_mb": 100
      }
    }
  ],
  "total": 42
}
```

#### POST /scans
Start a new scan.

**Request Body:**
```json
{
  "project_id": "uuid",
  "scan_path": "/path/to/scan",
  "scan_config": {
    "threads": 8,
    "timeout_seconds": 600,
    "max_file_size_mb": 50,
    "include_patterns": ["*.py", "*.js"],
    "exclude_patterns": ["node_modules/**", ".git/**"]
  },
  "webhook_on_completion": true
}
```

**Response:**
```json
{
  "scan_id": "uuid",
  "status": "queued",
  "estimated_start_time": "2025-01-15T10:00:00Z"
}
```

#### GET /scans/{scan_id}
Get detailed scan information.

#### GET /scans/{scan_id}/logs
Get scan execution logs.

### Reports

#### GET /reports/summary
Get summary statistics.

**Parameters:**
- `project_id` (string, optional): Filter by project
- `start_date` (string, optional): Start date (ISO 8601)
- `end_date` (string, optional): End date (ISO 8601)

**Response:**
```json
{
  "summary": {
    "total_projects": 5,
    "total_scans": 247,
    "total_findings": 8750,
    "findings_by_severity": {
      "critical": 45,
      "high": 234,
      "medium": 1234,
      "low": 7237
    },
    "findings_by_status": {
      "new": 1250,
      "acknowledged": 2500,
      "resolved": 4000,
      "false_positive": 1000
    },
    "top_secret_types": [
      {"type": "AWS API Key", "count": 1200},
      {"type": "GitHub Token", "count": 950},
      {"type": "Database Password", "count": 780}
    ]
  },
  "trends": {
    "daily_findings": [
      {"date": "2025-01-14", "count": 45},
      {"date": "2025-01-15", "count": 52}
    ]
  }
}
```

#### GET /reports/export
Export findings to various formats.

**Parameters:**
- `format` (string, required): Export format (`csv`, `json`, `pdf`)
- `project_id` (string, optional): Filter by project
- `start_date` (string, optional): Start date filter
- `end_date` (string, optional): End date filter

### Health & System

#### GET /health
System health check.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:00:00Z",
  "services": {
    "database": "healthy",
    "redis": "healthy",
    "scanner": "healthy"
  },
  "version": "2.1.0"
}
```

#### GET /system/info
Get system information.

**Response:**
```json
{
  "version": "2.1.0",
  "build_date": "2025-01-10T15:30:00Z",
  "python_version": "3.11.0",
  "database_version": "PostgreSQL 15.0",
  "redis_version": "7.0.0",
  "system_info": {
    "os": "Linux",
    "architecture": "x86_64",
    "cpu_count": 8,
    "memory_gb": 16
  }
}
```

## 📊 Rate Limits

- **Authenticated requests**: 1000 per hour
- **Anonymous requests**: 100 per hour
- **Scan requests**: 10 per hour per project

## 🚨 Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": {
      "field": "project_id",
      "reason": "Project not found"
    }
  },
  "timestamp": "2025-01-15T10:00:00Z",
  "request_id": "req-12345"
}
```

### Common Error Codes

- `VALIDATION_ERROR`: Invalid request parameters
- `AUTHENTICATION_ERROR`: Authentication failed
- `AUTHORIZATION_ERROR`: Insufficient permissions
- `NOT_FOUND`: Resource not found
- `CONFLICT`: Resource conflict
- `RATE_LIMITED`: Rate limit exceeded
- `INTERNAL_ERROR`: Internal server error

## 🔗 Webhook Integration

Configure webhooks to receive real-time notifications:

```json
{
  "webhook": {
    "enabled": true,
    "url": "https://your-endpoint.com/webhook",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer your-token",
      "Content-Type": "application/json"
    },
    "events": ["new_finding", "scan_completed", "scan_failed"]
  }
}
```

### Webhook Payload Examples

**New Finding:**
```json
{
  "event": "new_finding",
  "timestamp": "2025-01-15T10:30:00Z",
  "finding": {
    "id": "uuid",
    "project_id": "uuid",
    "file_path": "/path/to/file.py",
    "secret_type": "AWS API Key",
    "severity": "high",
    "context": "aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'"
  }
}
```

**Scan Completed:**
```json
{
  "event": "scan_completed",
  "timestamp": "2025-01-15T10:30:00Z",
  "scan": {
    "id": "uuid",
    "project_id": "uuid",
    "status": "completed",
    "files_scanned": 15420,
    "findings_count": 1250,
    "duration_seconds": 1800
  }
}
```

## 📝 Examples

### Python Client

```python
import requests
from requests.auth import HTTPBasicAuth

class SecretSnipeClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.auth = HTTPBasicAuth(username, password)

    def get_projects(self):
        response = requests.get(
            f"{self.base_url}/projects",
            auth=self.auth
        )
        return response.json()

    def start_scan(self, project_id, scan_path):
        response = requests.post(
            f"{self.base_url}/scans",
            auth=self.auth,
            json={
                "project_id": project_id,
                "scan_path": scan_path
            }
        )
        return response.json()
```

### JavaScript Client

```javascript
class SecretSnipeAPI {
    constructor(baseURL, username, password) {
        this.baseURL = baseURL;
        this.credentials = btoa(`${username}:${password}`);
    }

    async getFindings(projectId, filters = {}) {
        const params = new URLSearchParams({
            project_id: projectId,
            ...filters
        });

        const response = await fetch(
            `${this.baseURL}/findings?${params}`,
            {
                headers: {
                    'Authorization': `Basic ${this.credentials}`
                }
            }
        );

        return response.json();
    }

    async acknowledgeFinding(findingId, comment) {
        const response = await fetch(
            `${this.baseURL}/findings/${findingId}/acknowledge`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Basic ${this.credentials}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ comment })
            }
        );

        return response.json();
    }
}
```

---

*Last updated: September 19, 2025*