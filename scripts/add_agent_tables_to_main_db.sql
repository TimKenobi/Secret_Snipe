-- SecretSnipe Agent Management Schema Extension
-- This extends the main SecretSnipe database with agent management tables
-- Run this against the main secretsnipe database (not the separate agent db)

-- Enable required extensions (if not already enabled)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- AGENT INFRASTRUCTURE TABLES
-- ============================================================================

-- Registered scanning agents
CREATE TABLE IF NOT EXISTS agents (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    os_type VARCHAR(50),
    os_version VARCHAR(100),
    agent_version VARCHAR(50),
    capabilities JSONB DEFAULT '[]'::jsonb,
    scan_paths JSONB DEFAULT '[]'::jsonb,
    status VARCHAR(50) DEFAULT 'pending',  -- pending, online, offline, error, updating
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    config_version INTEGER DEFAULT 0,
    update_available BOOLEAN DEFAULT FALSE,
    machine_fingerprint VARCHAR(64),
    
    -- Ensure unique agent per host
    CONSTRAINT unique_agent_hostname_ip UNIQUE (hostname, ip_address)
);

-- API keys for agent authentication
CREATE TABLE IF NOT EXISTS agent_api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    key_prefix VARCHAR(16) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    permissions JSONB DEFAULT '["agent:register", "agent:heartbeat", "jobs:poll", "findings:submit"]'::jsonb,
    rate_limit INTEGER DEFAULT 1000,  -- requests per minute
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(255)
);

-- Agent heartbeat history (for monitoring/alerting)
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL,
    cpu_percent FLOAT,
    memory_percent FLOAT,
    disk_percent FLOAT,
    active_scans INTEGER DEFAULT 0,
    uptime_seconds BIGINT,
    last_error TEXT,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scan jobs assigned to agents
CREATE TABLE IF NOT EXISTS agent_jobs (
    id SERIAL PRIMARY KEY,
    job_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES agents(agent_id) ON DELETE SET NULL,
    job_type VARCHAR(50) DEFAULT 'scan',  -- scan, file_watch, scheduled_scan, update
    status VARCHAR(50) DEFAULT 'pending',  -- pending, assigned, running, completed, failed, cancelled
    priority INTEGER DEFAULT 5,  -- 1=highest, 10=lowest
    scan_paths JSONB DEFAULT '[]'::jsonb,
    scanners JSONB DEFAULT '["custom", "trufflehog", "gitleaks"]'::jsonb,
    config JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_at TIMESTAMP WITH TIME ZONE,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    files_scanned INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    error_message TEXT,
    result_summary JSONB DEFAULT '{}'::jsonb,
    
    -- Link to main project if applicable
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL
);

-- Agent-discovered findings (synced to main findings table)
CREATE TABLE IF NOT EXISTS agent_findings (
    id SERIAL PRIMARY KEY,
    finding_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES agent_jobs(job_id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(agent_id) ON DELETE SET NULL,
    
    -- Finding details (mirrors main findings table structure)
    secret_type VARCHAR(255) NOT NULL,
    secret_value TEXT,  -- Masked/encrypted
    file_path TEXT NOT NULL,
    line_number INTEGER,
    column_start INTEGER,
    column_end INTEGER,
    line_content TEXT,
    context_before TEXT,
    context_after TEXT,
    
    -- Detection info
    scanner VARCHAR(50) NOT NULL,  -- custom, trufflehog, gitleaks
    pattern_name VARCHAR(255),
    confidence FLOAT DEFAULT 0.9,
    severity VARCHAR(50) DEFAULT 'High',  -- Critical, High, Medium, Low, Info
    
    -- Status tracking
    status VARCHAR(50) DEFAULT 'open',  -- open, resolved, false_positive, accepted_risk
    is_false_positive BOOLEAN DEFAULT FALSE,
    reviewed_by VARCHAR(255),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,
    
    -- Metadata
    hostname VARCHAR(255),
    found_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb,
    fingerprint VARCHAR(64) UNIQUE,  -- For deduplication
    
    -- Link to main findings table (after sync)
    synced_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    synced_at TIMESTAMP WITH TIME ZONE
);

-- Scheduled scans
CREATE TABLE IF NOT EXISTS agent_schedules (
    id SERIAL PRIMARY KEY,
    schedule_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    cron_expression VARCHAR(100) NOT NULL,
    scan_paths JSONB DEFAULT '[]'::jsonb,
    scanners JSONB DEFAULT '{"custom": true, "gitleaks": true, "trufflehog": true}'::jsonb,
    enabled BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP WITH TIME ZONE,
    next_run TIMESTAMP WITH TIME ZONE,
    last_status VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- Watch paths for file system monitoring
CREATE TABLE IF NOT EXISTS agent_watch_paths (
    id SERIAL PRIMARY KEY,
    watch_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    recursive BOOLEAN DEFAULT TRUE,
    file_patterns JSONB DEFAULT '["*"]'::jsonb,
    exclude_patterns JSONB DEFAULT '["node_modules", ".git", "__pycache__", "*.pyc", "*.log"]'::jsonb,
    enabled BOOLEAN DEFAULT TRUE,
    last_event TIMESTAMP WITH TIME ZONE,
    total_events INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Agent configuration (remote push)
CREATE TABLE IF NOT EXISTS agent_configs (
    id SERIAL PRIMARY KEY,
    config_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES agents(agent_id) ON DELETE CASCADE,  -- NULL = global config
    config_key VARCHAR(255) NOT NULL,
    config_value JSONB NOT NULL,
    version INTEGER DEFAULT 1,
    effective_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255),
    
    UNIQUE(agent_id, config_key)
);

-- Agent logs (streamed from agents)
CREATE TABLE IF NOT EXISTS agent_logs (
    id SERIAL PRIMARY KEY,
    log_id UUID DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    level VARCHAR(20) NOT NULL,  -- DEBUG, INFO, WARNING, ERROR, CRITICAL
    message TEXT NOT NULL,
    source VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Agent updates/versions
CREATE TABLE IF NOT EXISTS agent_updates (
    id SERIAL PRIMARY KEY,
    update_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    version VARCHAR(50) NOT NULL,
    release_notes TEXT,
    download_url TEXT,
    checksum VARCHAR(128),
    min_agent_version VARCHAR(50),  -- Minimum version that can upgrade to this
    is_mandatory BOOLEAN DEFAULT FALSE,
    release_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Agents
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_heartbeat ON agents(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname);

-- Heartbeats (keep recent, partition by time if needed)
CREATE INDEX IF NOT EXISTS idx_heartbeats_agent_recorded ON agent_heartbeats(agent_id, recorded_at DESC);

-- Jobs
CREATE INDEX IF NOT EXISTS idx_jobs_status ON agent_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_agent ON agent_jobs(agent_id);
CREATE INDEX IF NOT EXISTS idx_jobs_pending ON agent_jobs(status, priority) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_jobs_created ON agent_jobs(created_at DESC);

-- Findings
CREATE INDEX IF NOT EXISTS idx_agent_findings_job ON agent_findings(job_id);
CREATE INDEX IF NOT EXISTS idx_agent_findings_agent ON agent_findings(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_findings_status ON agent_findings(status);
CREATE INDEX IF NOT EXISTS idx_agent_findings_severity ON agent_findings(severity);
CREATE INDEX IF NOT EXISTS idx_agent_findings_found ON agent_findings(found_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_findings_fingerprint ON agent_findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_agent_findings_sync ON agent_findings(synced_finding_id) WHERE synced_finding_id IS NULL;

-- Logs (time-based queries)
CREATE INDEX IF NOT EXISTS idx_agent_logs_agent_time ON agent_logs(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_agent_logs_level ON agent_logs(level, timestamp DESC);

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Automatically update agent status based on heartbeat timeout
CREATE OR REPLACE FUNCTION mark_offline_agents()
RETURNS void AS $$
BEGIN
    UPDATE agents 
    SET status = 'offline'
    WHERE status NOT IN ('offline', 'pending', 'error')
    AND last_heartbeat < NOW() - INTERVAL '2 minutes';
END;
$$ LANGUAGE plpgsql;

-- Sync agent findings to main findings table
CREATE OR REPLACE FUNCTION sync_agent_finding_to_main(p_agent_finding_id UUID)
RETURNS UUID AS $$
DECLARE
    v_finding_id UUID;
    v_project_id UUID;
    v_scan_session_id UUID;
BEGIN
    -- Get or create project for the agent
    SELECT id INTO v_project_id 
    FROM projects 
    WHERE name = (SELECT hostname FROM agents WHERE agent_id = (
        SELECT agent_id FROM agent_findings WHERE finding_id = p_agent_finding_id
    ))
    LIMIT 1;
    
    -- Create project if not exists
    IF v_project_id IS NULL THEN
        INSERT INTO projects (name, description, is_active)
        SELECT hostname, 'Auto-created from agent scan', true
        FROM agents WHERE agent_id = (
            SELECT agent_id FROM agent_findings WHERE finding_id = p_agent_finding_id
        )
        RETURNING id INTO v_project_id;
    END IF;
    
    -- Insert into main findings table
    INSERT INTO findings (
        project_id, file_path, line_number, secret_type, 
        secret_value, context, severity, is_valid, confidence_score,
        tool_source, fingerprint, first_seen, last_seen
    )
    SELECT 
        v_project_id,
        af.file_path,
        af.line_number,
        af.secret_type,
        af.secret_value,
        af.line_content,
        af.severity,
        NOT af.is_false_positive,
        af.confidence,
        af.scanner,
        af.fingerprint,
        af.found_at,
        af.found_at
    FROM agent_findings af
    WHERE af.finding_id = p_agent_finding_id
    ON CONFLICT (fingerprint) DO UPDATE SET
        last_seen = NOW()
    RETURNING id INTO v_finding_id;
    
    -- Update agent_findings with sync reference
    UPDATE agent_findings 
    SET synced_finding_id = v_finding_id, synced_at = NOW()
    WHERE finding_id = p_agent_finding_id;
    
    RETURN v_finding_id;
END;
$$ LANGUAGE plpgsql;

-- Clean up old heartbeat records (keep last 24 hours)
CREATE OR REPLACE FUNCTION cleanup_old_heartbeats()
RETURNS void AS $$
BEGIN
    DELETE FROM agent_heartbeats 
    WHERE recorded_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Clean up old logs (keep last 7 days)
CREATE OR REPLACE FUNCTION cleanup_old_agent_logs()
RETURNS void AS $$
BEGIN
    DELETE FROM agent_logs 
    WHERE received_at < NOW() - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Active agents summary
CREATE OR REPLACE VIEW v_agent_summary AS
SELECT 
    a.agent_id,
    a.hostname,
    a.ip_address,
    a.os_type,
    a.agent_version,
    a.status,
    a.last_heartbeat,
    EXTRACT(EPOCH FROM (NOW() - a.last_heartbeat)) as seconds_since_heartbeat,
    COUNT(DISTINCT aj.job_id) FILTER (WHERE aj.status = 'running') as active_jobs,
    COUNT(DISTINCT af.finding_id) FILTER (WHERE af.status = 'open') as open_findings,
    a.registered_at,
    a.capabilities
FROM agents a
LEFT JOIN agent_jobs aj ON a.agent_id = aj.agent_id
LEFT JOIN agent_findings af ON a.agent_id = af.agent_id
GROUP BY a.agent_id, a.hostname, a.ip_address, a.os_type, a.agent_version, 
         a.status, a.last_heartbeat, a.registered_at, a.capabilities;

-- Recent findings from agents
CREATE OR REPLACE VIEW v_recent_agent_findings AS
SELECT 
    af.finding_id,
    af.secret_type,
    af.file_path,
    af.line_number,
    af.severity,
    af.scanner,
    af.status,
    af.found_at,
    a.hostname,
    a.ip_address,
    aj.job_id,
    af.synced_finding_id IS NOT NULL as is_synced
FROM agent_findings af
JOIN agents a ON af.agent_id = a.agent_id
LEFT JOIN agent_jobs aj ON af.job_id = aj.job_id
ORDER BY af.found_at DESC
LIMIT 500;

-- Dashboard statistics
CREATE OR REPLACE VIEW v_agent_dashboard_stats AS
SELECT
    (SELECT COUNT(*) FROM agents WHERE status = 'online') as online_agents,
    (SELECT COUNT(*) FROM agents WHERE status = 'offline') as offline_agents,
    (SELECT COUNT(*) FROM agents WHERE status = 'error') as error_agents,
    (SELECT COUNT(*) FROM agent_jobs WHERE status = 'pending') as pending_jobs,
    (SELECT COUNT(*) FROM agent_jobs WHERE status = 'running') as running_jobs,
    (SELECT COUNT(*) FROM agent_findings WHERE status = 'open') as open_findings,
    (SELECT COUNT(*) FROM agent_findings WHERE status = 'open' AND severity = 'Critical') as critical_findings,
    (SELECT COUNT(*) FROM agent_findings WHERE status = 'open' AND severity = 'High') as high_findings,
    (SELECT COUNT(*) FROM agent_findings WHERE found_at > NOW() - INTERVAL '24 hours') as findings_last_24h,
    (SELECT SUM(files_scanned) FROM agent_jobs WHERE completed_at > NOW() - INTERVAL '24 hours') as files_scanned_24h;

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert default API key (same as agent_project for compatibility)
INSERT INTO agent_api_keys (key_hash, key_prefix, name, description, created_by)
VALUES (
    encode(digest('G7HEyqLjUfpB-nes--YzsbYMYXuQNiQfeYDjxuxUSC5-nDZBylR8CsMr_PtsWQSdR-Sz7jsUwdMDCMpefPSX2w', 'sha256'), 'hex'),
    'G7HEyqLj',
    'Default Agent Key',
    'Default API key for agent authentication - replace in production',
    'system'
) ON CONFLICT (key_hash) DO NOTHING;

-- Insert default global config
INSERT INTO agent_configs (agent_id, config_key, config_value, created_by)
VALUES 
    (NULL, 'scan_settings', '{"max_file_size_mb": 50, "excluded_extensions": [".exe", ".dll", ".so", ".bin"], "excluded_paths": ["node_modules", ".git", "__pycache__"]}'::jsonb, 'system'),
    (NULL, 'alert_settings', '{"email_on_critical": true, "slack_webhook": null, "pagerduty_key": null}'::jsonb, 'system'),
    (NULL, 'retention_settings', '{"findings_days": 365, "logs_days": 30, "heartbeats_hours": 24}'::jsonb, 'system')
ON CONFLICT (agent_id, config_key) DO NOTHING;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE agents IS 'Registered SecretSnipe scanning agents';
COMMENT ON TABLE agent_jobs IS 'Scan jobs assigned to agents';
COMMENT ON TABLE agent_findings IS 'Secrets discovered by agents - synced to main findings table';
COMMENT ON TABLE agent_schedules IS 'Scheduled recurring scans per agent';
COMMENT ON TABLE agent_watch_paths IS 'File system paths monitored by agents in real-time';
COMMENT ON TABLE agent_logs IS 'Log entries streamed from agents';
COMMENT ON VIEW v_agent_summary IS 'Summary view of all agents with current status';
COMMENT ON VIEW v_agent_dashboard_stats IS 'Aggregate statistics for agent dashboard';
