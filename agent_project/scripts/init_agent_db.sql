-- SecretSnipe Agent Database Initialization Script
-- This creates all required tables for agent management

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- API Keys table
CREATE TABLE IF NOT EXISTS agent_api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    key_prefix VARCHAR(16) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(255)
);

-- Agents table
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
    status VARCHAR(50) DEFAULT 'pending',
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Agent heartbeats table (for tracking history)
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL,
    cpu_percent FLOAT,
    memory_percent FLOAT,
    disk_percent FLOAT,
    active_scans INTEGER DEFAULT 0,
    uptime_seconds INTEGER,
    last_error TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agent jobs table
CREATE TABLE IF NOT EXISTS agent_jobs (
    id SERIAL PRIMARY KEY,
    job_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES agents(agent_id) ON DELETE SET NULL,
    job_type VARCHAR(50) DEFAULT 'full_scan',
    status VARCHAR(50) DEFAULT 'pending',
    priority INTEGER DEFAULT 5,
    scan_paths JSONB DEFAULT '[]'::jsonb,
    scanners JSONB DEFAULT '["custom", "trufflehog", "gitleaks"]'::jsonb,
    config JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    files_scanned INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    error_message TEXT,
    result_summary JSONB DEFAULT '{}'::jsonb
);

-- Agent findings table (stores secrets found by agents)
CREATE TABLE IF NOT EXISTS agent_findings (
    id SERIAL PRIMARY KEY,
    finding_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES agent_jobs(job_id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(agent_id) ON DELETE SET NULL,
    
    -- Finding details
    secret_type VARCHAR(100) NOT NULL,
    secret_value TEXT,  -- Encrypted/redacted
    file_path TEXT NOT NULL,
    line_number INTEGER,
    column_start INTEGER,
    column_end INTEGER,
    line_content TEXT,
    context_before TEXT,
    context_after TEXT,
    
    -- Detection info
    scanner VARCHAR(50) NOT NULL,  -- 'custom', 'trufflehog', 'gitleaks'
    pattern_name VARCHAR(255),
    confidence FLOAT DEFAULT 0.9,
    severity VARCHAR(20) DEFAULT 'high',
    
    -- Status tracking
    status VARCHAR(50) DEFAULT 'open',
    is_false_positive BOOLEAN DEFAULT FALSE,
    reviewed_by VARCHAR(255),
    reviewed_at TIMESTAMP,
    notes TEXT,
    
    -- Metadata
    hostname VARCHAR(255),
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_heartbeat ON agents(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_heartbeats_agent_id ON agent_heartbeats(agent_id);
CREATE INDEX IF NOT EXISTS idx_heartbeats_recorded_at ON agent_heartbeats(recorded_at);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON agent_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_agent_id ON agent_jobs(agent_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON agent_jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_job_id ON agent_findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_agent_id ON agent_findings(agent_id);
CREATE INDEX IF NOT EXISTS idx_findings_secret_type ON agent_findings(secret_type);
CREATE INDEX IF NOT EXISTS idx_findings_status ON agent_findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_found_at ON agent_findings(found_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON agent_api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON agent_api_keys(is_active);

-- Function to update agent status based on heartbeat
CREATE OR REPLACE FUNCTION update_agent_status_on_heartbeat()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE agents 
    SET last_heartbeat = NEW.recorded_at,
        status = NEW.status
    WHERE agent_id = NEW.agent_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for automatic status update
DROP TRIGGER IF EXISTS trg_update_agent_status ON agent_heartbeats;
CREATE TRIGGER trg_update_agent_status
    AFTER INSERT ON agent_heartbeats
    FOR EACH ROW
    EXECUTE FUNCTION update_agent_status_on_heartbeat();

-- Function to mark agents offline if no heartbeat
CREATE OR REPLACE FUNCTION mark_stale_agents_offline()
RETURNS void AS $$
BEGIN
    UPDATE agents 
    SET status = 'offline'
    WHERE status NOT IN ('offline', 'pending')
    AND last_heartbeat < NOW() - INTERVAL '2 minutes';
END;
$$ LANGUAGE plpgsql;

-- View for agent summary stats
CREATE OR REPLACE VIEW agent_summary AS
SELECT 
    status,
    COUNT(*) as count,
    AVG(EXTRACT(EPOCH FROM (NOW() - last_heartbeat))) as avg_seconds_since_heartbeat
FROM agents
GROUP BY status;

-- View for job summary stats
CREATE OR REPLACE VIEW job_summary AS
SELECT 
    status,
    COUNT(*) as count,
    SUM(findings_count) as total_findings,
    SUM(files_scanned) as total_files_scanned
FROM agent_jobs
GROUP BY status;

-- View for recent findings
CREATE OR REPLACE VIEW recent_findings AS
SELECT 
    f.finding_id,
    f.secret_type,
    f.file_path,
    f.line_number,
    f.scanner,
    f.severity,
    f.status,
    f.found_at,
    a.hostname,
    j.job_id
FROM agent_findings f
LEFT JOIN agents a ON f.agent_id = a.agent_id
LEFT JOIN agent_jobs j ON f.job_id = j.job_id
ORDER BY f.found_at DESC
LIMIT 100;

-- Grant permissions (if needed for specific users)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO secretsnipe;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO secretsnipe;

COMMENT ON TABLE agents IS 'Registered scanning agents';
COMMENT ON TABLE agent_jobs IS 'Scan jobs assigned to agents';
COMMENT ON TABLE agent_findings IS 'Secrets/credentials found by agents';
COMMENT ON TABLE agent_heartbeats IS 'Agent heartbeat history for monitoring';
COMMENT ON TABLE agent_api_keys IS 'API keys for agent authentication';
