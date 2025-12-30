-- Migration: Add scan directories management
-- Run this when ready to enable multi-directory scanning

-- Table for managing multiple scan directories
CREATE TABLE IF NOT EXISTS scan_directories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    directory_path TEXT NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    scan_priority INTEGER DEFAULT 5, -- 1=highest, 10=lowest
    last_scan_at TIMESTAMP WITH TIME ZONE,
    last_scan_status VARCHAR(50), -- 'completed', 'failed', 'running'
    total_files INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    scan_schedule VARCHAR(50) DEFAULT 'daily', -- 'hourly', 'daily', 'weekly', 'manual'
    exclude_patterns TEXT[], -- Patterns to exclude from scan
    include_patterns TEXT[], -- Patterns to include (if set, only these)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Table for tracking manual/on-demand scan requests
CREATE TABLE IF NOT EXISTS scan_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    directory_id UUID REFERENCES scan_directories(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL DEFAULT 'full', -- 'full', 'incremental', 'custom_only', 'trufflehog_only', 'gitleaks_only'
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'queued', 'running', 'completed', 'failed', 'cancelled'
    requested_by VARCHAR(255) DEFAULT 'dashboard_user',
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    files_scanned INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    error_message TEXT,
    scan_options JSONB DEFAULT '{}'
);

-- Index for efficient directory lookups
CREATE INDEX IF NOT EXISTS idx_scan_directories_active ON scan_directories(is_active, scan_priority);
CREATE INDEX IF NOT EXISTS idx_scan_directories_path ON scan_directories(directory_path);
CREATE INDEX IF NOT EXISTS idx_scan_requests_status ON scan_requests(status, requested_at);
CREATE INDEX IF NOT EXISTS idx_scan_requests_directory ON scan_requests(directory_id, status);

-- Insert default scan directory (the current /scan mount)
INSERT INTO scan_directories (project_id, directory_path, display_name, description, is_active)
SELECT 
    p.id,
    '/scan',
    'Primary Scan Directory',
    'Main mounted scan directory - original mount point'
FROM projects p
WHERE p.name = 'Default Project'
ON CONFLICT (directory_path) DO NOTHING;

-- View for easy directory status checking
CREATE OR REPLACE VIEW v_scan_directory_status AS
SELECT 
    sd.id,
    sd.display_name,
    sd.directory_path,
    sd.is_active,
    sd.scan_priority,
    sd.scan_schedule,
    sd.last_scan_at,
    sd.last_scan_status,
    sd.total_files,
    sd.total_findings,
    p.name as project_name,
    (SELECT COUNT(*) FROM scan_requests sr WHERE sr.directory_id = sd.id AND sr.status IN ('pending', 'queued', 'running')) as pending_scans
FROM scan_directories sd
JOIN projects p ON sd.project_id = p.id
ORDER BY sd.scan_priority, sd.display_name;

COMMENT ON TABLE scan_directories IS 'Manages multiple directories for scanning - enables multi-project support';
COMMENT ON TABLE scan_requests IS 'Tracks manual/on-demand scan requests from the dashboard';
