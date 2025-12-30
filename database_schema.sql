-- SecretSnipe PostgreSQL Database Schema
-- Unified schema for custom scanner, Trufflehog, and Gitleaks
-- Supports configurable reports and webhook notifications

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For text search
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- For indexing arrays

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Projects/Repositories being scanned
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    repository_url TEXT,
    local_path TEXT,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_scan_at TIMESTAMP WITH TIME ZONE,
    scan_frequency INTERVAL DEFAULT '1 day',
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}'
);

-- Individual scan sessions
CREATE TABLE scan_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL, -- 'custom', 'trufflehog', 'gitleaks', 'combined'
    status VARCHAR(50) DEFAULT 'running', -- 'running', 'completed', 'failed', 'cancelled'
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    total_files_scanned INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    scan_parameters JSONB DEFAULT '{}',
    error_message TEXT,
    created_by VARCHAR(255)
);

-- ============================================================================
-- FINDINGS TABLES
-- ============================================================================

-- Main findings table - unified format for all tools
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_session_id UUID REFERENCES scan_sessions(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,

    -- Core finding data
    file_path TEXT NOT NULL,
    line_number INTEGER,
    secret_type VARCHAR(255) NOT NULL,
    secret_value TEXT, -- Masked/encrypted in production
    context TEXT,
    severity VARCHAR(50) DEFAULT 'Medium', -- 'Critical', 'High', 'Medium', 'Low', 'Info'

    -- Validation and metadata
    is_valid BOOLEAN DEFAULT true,
    validation_reason TEXT,
    confidence_score DECIMAL(3,2), -- 0.00 to 1.00
    tool_source VARCHAR(100) NOT NULL, -- 'custom', 'trufflehog', 'gitleaks'

    -- Additional metadata
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_status VARCHAR(50) DEFAULT 'open', -- 'open', 'resolved', 'false_positive', 'accepted_risk'

    -- Deduplication
    fingerprint VARCHAR(255) UNIQUE, -- Hash for deduplication
    duplicate_of UUID REFERENCES findings(id),

    -- Audit trail
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Finding history for tracking changes
CREATE TABLE finding_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    field_changed VARCHAR(100),
    old_value TEXT,
    new_value TEXT,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- REPORTING AND NOTIFICATIONS
-- ============================================================================

-- Report templates
CREATE TABLE report_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    template_type VARCHAR(50) DEFAULT 'summary', -- 'summary', 'detailed', 'executive'
    format VARCHAR(50) DEFAULT 'html', -- 'html', 'pdf', 'json', 'csv'

    -- Template configuration
    filters JSONB DEFAULT '{}', -- severity, tool, date range, etc.
    sections JSONB DEFAULT '[]', -- which sections to include
    styling JSONB DEFAULT '{}', -- colors, fonts, etc.

    -- Scheduling
    is_scheduled BOOLEAN DEFAULT false,
    schedule_cron VARCHAR(100),
    recipients TEXT[] DEFAULT '{}',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- Generated reports
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id UUID REFERENCES report_templates(id),
    title VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'generating', -- 'generating', 'completed', 'failed'

    -- Report data
    parameters JSONB DEFAULT '{}',
    content TEXT, -- HTML/PDF content or file path
    file_path TEXT,
    file_size INTEGER,

    -- Metadata
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    generated_by VARCHAR(255),
    execution_time INTERVAL
);

-- Webhook configurations
CREATE TABLE webhook_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    url TEXT NOT NULL,
    method VARCHAR(10) DEFAULT 'POST',
    headers JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,

    -- Trigger conditions
    trigger_on_severity VARCHAR(50)[] DEFAULT '{"Critical", "High"}',
    trigger_on_tools VARCHAR(100)[] DEFAULT '{}',
    trigger_on_new_findings BOOLEAN DEFAULT true,
    trigger_on_resolved BOOLEAN DEFAULT false,

    -- Authentication
    auth_type VARCHAR(50), -- 'none', 'basic', 'bearer', 'api_key'
    auth_config JSONB DEFAULT '{}',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Webhook delivery history
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_config_id UUID REFERENCES webhook_configs(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,

    -- Delivery details
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'sent', 'failed', 'retry'
    attempt_count INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,

    -- Request/Response
    request_payload JSONB,
    response_status INTEGER,
    response_body TEXT,
    error_message TEXT,

    -- Timestamps
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    sent_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- ============================================================================
-- CONFIGURATION AND METADATA
-- ============================================================================

-- Application configuration
CREATE TABLE app_config (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(255)
);

-- File processing cache
CREATE TABLE file_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_path TEXT NOT NULL,
    file_hash VARCHAR(128) NOT NULL,
    last_modified TIMESTAMP WITH TIME ZONE,
    scan_session_id UUID REFERENCES scan_sessions(id),
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(file_path, file_hash)
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Findings indexes
CREATE INDEX idx_findings_scan_session ON findings(scan_session_id);
CREATE INDEX idx_findings_project ON findings(project_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_tool_source ON findings(tool_source);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_resolution_status ON findings(resolution_status);
CREATE INDEX idx_findings_first_seen ON findings(first_seen);
CREATE INDEX idx_findings_last_seen ON findings(last_seen);

-- Composite indexes for common dashboard queries
CREATE INDEX idx_findings_resolution_first_seen ON findings(resolution_status, first_seen DESC);
CREATE INDEX idx_findings_tool_resolution ON findings(tool_source, resolution_status);
CREATE INDEX idx_findings_severity_resolution ON findings(severity, resolution_status);
CREATE INDEX idx_findings_file_resolution ON findings(file_path, resolution_status);
CREATE INDEX idx_findings_secret_type ON findings(secret_type);

-- Text search indexes
CREATE INDEX idx_findings_file_path_gin ON findings USING gin(file_path gin_trgm_ops);
CREATE INDEX idx_findings_secret_type_gin ON findings USING gin(secret_type gin_trgm_ops);
CREATE INDEX idx_findings_tags_gin ON findings USING gin(tags);

-- Scan sessions indexes
CREATE INDEX idx_scan_sessions_project ON scan_sessions(project_id);
CREATE INDEX idx_scan_sessions_status ON scan_sessions(status);
CREATE INDEX idx_scan_sessions_started ON scan_sessions(started_at);

-- Projects indexes
CREATE INDEX idx_projects_active ON projects(is_active);
CREATE INDEX idx_projects_last_scan ON projects(last_scan_at);

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active findings view
CREATE VIEW active_findings AS
SELECT f.*, p.name as project_name, ss.scan_type
FROM findings f
JOIN projects p ON f.project_id = p.id
JOIN scan_sessions ss ON f.scan_session_id = ss.id
WHERE f.resolution_status = 'open'
AND p.is_active = true;

-- Critical findings view
CREATE VIEW critical_findings AS
SELECT * FROM active_findings
WHERE severity IN ('Critical', 'High')
ORDER BY first_seen DESC;

-- Recent scan summary view
CREATE VIEW scan_summary AS
SELECT
    ss.id,
    ss.project_id,
    p.name as project_name,
    ss.scan_type,
    ss.status,
    ss.started_at,
    ss.completed_at,
    ss.total_files_scanned,
    ss.total_findings,
    COUNT(f.id) as active_findings,
    COUNT(CASE WHEN f.severity = 'Critical' THEN 1 END) as critical_findings,
    COUNT(CASE WHEN f.severity = 'High' THEN 1 END) as high_findings
FROM scan_sessions ss
JOIN projects p ON ss.project_id = p.id
LEFT JOIN findings f ON ss.id = f.scan_session_id AND f.resolution_status = 'open'
GROUP BY ss.id, ss.project_id, p.name, ss.scan_type, ss.status, ss.started_at, ss.completed_at, ss.total_files_scanned, ss.total_findings;

-- ============================================================================
-- FUNCTIONS AND TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers
CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_report_templates_updated_at BEFORE UPDATE ON report_templates FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_webhook_configs_updated_at BEFORE UPDATE ON webhook_configs FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to generate finding fingerprint
CREATE OR REPLACE FUNCTION generate_finding_fingerprint(
    p_file_path TEXT,
    p_secret_type TEXT,
    p_secret_value TEXT,
    p_line_number INTEGER DEFAULT NULL
)
RETURNS VARCHAR(255) AS $$
BEGIN
    RETURN encode(
        sha256(
            (COALESCE(p_file_path, '') || '|' ||
             COALESCE(p_secret_type, '') || '|' ||
             COALESCE(p_secret_value, '') || '|' ||
             COALESCE(p_line_number::TEXT, ''))::bytea
        ),
        'hex'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert default configuration
INSERT INTO app_config (key, value, description) VALUES
('scanner.threads', '4', 'Number of scanning threads'),
('scanner.timeout', '300', 'Scan timeout in seconds'),
('cache.ttl', '3600', 'Cache TTL in seconds'),
('webhook.retry_attempts', '3', 'Maximum webhook retry attempts'),
('report.retention_days', '90', 'Report retention period in days');

-- Insert default webhook config (disabled by default)
INSERT INTO webhook_configs (name, url, is_active) VALUES
('Default Webhook', 'https://example.com/webhook', false);