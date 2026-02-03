-- SecretSnipe Database Schema Migration V2
-- Enhanced findings management with categories, adjustable severity, 
-- file timestamps, proof content, and email notifications
-- 
-- Run this migration against your existing database:
-- psql -h localhost -U secretsnipe -d secretsnipe -f scripts/schema_migration_v2.sql

-- ============================================================================
-- ENHANCED FINDINGS COLUMNS
-- ============================================================================

-- Add finding category for better organization
-- Categories: finance_data, real_password, real_api_key, placeholder, test_data, sample_key, other
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_category VARCHAR(100) DEFAULT 'uncategorized';

-- Adjustable severity - keeps original and allows modification
ALTER TABLE findings ADD COLUMN IF NOT EXISTS original_severity VARCHAR(50);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS severity_adjusted_by VARCHAR(255);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS severity_adjusted_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS severity_adjustment_reason TEXT;

-- File staleness tracking
ALTER TABLE findings ADD COLUMN IF NOT EXISTS file_last_accessed TIMESTAMP WITH TIME ZONE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS file_created_at TIMESTAMP WITH TIME ZONE;

-- Full proof context - stores lines around the finding for review
ALTER TABLE findings ADD COLUMN IF NOT EXISTS proof_content TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS proof_start_line INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS proof_end_line INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS proof_context_lines INTEGER DEFAULT 10;

-- Owner assignment and escalation
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assigned_owner VARCHAR(255);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS owner_email VARCHAR(255);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS notification_sent_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS escalation_date TIMESTAMP WITH TIME ZONE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS escalation_status VARCHAR(50) DEFAULT 'none'; -- none, pending, escalated, resolved

-- Enhanced false positive categorization
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fp_category VARCHAR(100); -- placeholder_value, test_data, sample_key, commented_out, encoded_data, etc.

-- Parent folder for grouping
ALTER TABLE findings ADD COLUMN IF NOT EXISTS parent_folder TEXT;

-- ============================================================================
-- FINDING CATEGORIES LOOKUP TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS finding_categories (
    id SERIAL PRIMARY KEY,
    category_key VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    severity_weight INTEGER DEFAULT 0,  -- Affects severity calculation
    color_code VARCHAR(20) DEFAULT '#6b7280',
    icon VARCHAR(50),
    is_active BOOLEAN DEFAULT true,
    sort_order INTEGER DEFAULT 100,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default categories
INSERT INTO finding_categories (category_key, display_name, description, severity_weight, color_code, icon, sort_order) VALUES
    ('real_password', 'Real Password', 'Actual plaintext password used for authentication', 100, '#dc2626', '🔑', 10),
    ('real_api_key', 'Real API Key', 'Active API key or token with access to services', 90, '#ea580c', '🔐', 20),
    ('finance_data', 'Financial Data', 'Credit card numbers, bank accounts, financial credentials', 95, '#b91c1c', '💰', 15),
    ('database_credential', 'Database Credential', 'Database connection strings, usernames, passwords', 85, '#c026d3', '🗄️', 25),
    ('cloud_credential', 'Cloud Credential', 'AWS, Azure, GCP service credentials', 88, '#0ea5e9', '☁️', 22),
    ('private_key', 'Private Key', 'SSH keys, certificates, encryption keys', 92, '#7c3aed', '🔏', 18),
    ('placeholder', 'Placeholder/Example', 'Placeholder value like "YOUR_API_KEY_HERE"', -50, '#6b7280', '📝', 100),
    ('test_data', 'Test Data', 'Test credentials, mock data, unit test values', -40, '#22c55e', '🧪', 110),
    ('sample_key', 'Sample/Demo Key', 'Sample API keys from documentation or tutorials', -30, '#14b8a6', '📖', 120),
    ('commented_out', 'Commented Out', 'Code that is commented out but contains secrets', 20, '#f59e0b', '💬', 80),
    ('encoded_data', 'Encoded/Encrypted', 'Base64 or encrypted values that need decoding', 30, '#8b5cf6', '🔢', 70),
    ('environment_variable', 'Environment Variable', 'Secret stored/referenced via environment variable', 40, '#3b82f6', '🌐', 60),
    ('hardcoded', 'Hardcoded Secret', 'Secret hardcoded directly in source code', 80, '#ef4444', '⚠️', 30),
    ('config_file', 'Config File Secret', 'Secret in configuration file', 70, '#f97316', '⚙️', 40),
    ('uncategorized', 'Uncategorized', 'Finding has not been categorized yet', 0, '#9ca3af', '❓', 200)
ON CONFLICT (category_key) DO NOTHING;

-- ============================================================================
-- FALSE POSITIVE CATEGORIES
-- ============================================================================

CREATE TABLE IF NOT EXISTS fp_categories (
    id SERIAL PRIMARY KEY,
    category_key VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    auto_detect_patterns TEXT[],  -- Regex patterns that can auto-detect this category
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default FP categories
INSERT INTO fp_categories (category_key, display_name, description, auto_detect_patterns) VALUES
    ('placeholder_value', 'Placeholder Value', 'Generic placeholder like YOUR_KEY_HERE', ARRAY['YOUR_.*_HERE', 'REPLACE_.*', 'INSERT_.*_HERE', 'xxx+', '\*{4,}', '<.*>']),
    ('test_data', 'Test/Mock Data', 'Test data in unit tests or mock files', ARRAY['test', 'mock', 'fake', 'dummy', 'example']),
    ('sample_documentation', 'Sample from Docs', 'Sample values copied from documentation', ARRAY['example\.com', 'sample', 'demo', 'tutorial']),
    ('commented_code', 'Commented Code', 'Secret in commented-out code', ARRAY['^[/#\-]+\s*']),
    ('template_variable', 'Template Variable', 'Template substitution syntax', ARRAY['\$\{.*\}', '\{\{.*\}\}', '<%.*%>']),
    ('base64_noise', 'Base64 False Match', 'Base64 encoded text that is not a secret', NULL),
    ('hash_not_secret', 'Hash/Checksum', 'Hash value that is not a secret (SHA, MD5 checksums)', ARRAY['[a-f0-9]{32,64}']),
    ('public_key', 'Public Key', 'Public key (not private)', ARRAY['-----BEGIN PUBLIC KEY-----']),
    ('known_sample', 'Known Sample Key', 'Well-known sample API keys from tutorials', NULL),
    ('internal_only', 'Internal Network Only', 'Credentials for internal-only systems', NULL),
    ('other', 'Other', 'Other reason for false positive', NULL)
ON CONFLICT (category_key) DO NOTHING;

-- ============================================================================
-- EMAIL CONFIGURATION AND TEMPLATES
-- ============================================================================

CREATE TABLE IF NOT EXISTS email_config (
    id SERIAL PRIMARY KEY,
    config_name VARCHAR(100) UNIQUE NOT NULL DEFAULT 'default',
    smtp_host VARCHAR(255) NOT NULL,
    smtp_port INTEGER DEFAULT 587,
    smtp_username VARCHAR(255),
    smtp_password TEXT,  -- Should be encrypted in production
    smtp_use_tls BOOLEAN DEFAULT true,
    smtp_use_ssl BOOLEAN DEFAULT false,
    from_email VARCHAR(255) NOT NULL,
    from_name VARCHAR(255) DEFAULT 'SecretSnipe Security',
    reply_to_email VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    test_successful BOOLEAN DEFAULT false,
    last_test_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_templates (
    id SERIAL PRIMARY KEY,
    template_key VARCHAR(100) UNIQUE NOT NULL,
    template_name VARCHAR(255) NOT NULL,
    subject_template TEXT NOT NULL,
    body_template TEXT NOT NULL,
    body_html_template TEXT,
    description TEXT,
    available_variables TEXT[],  -- List of available template variables
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default email templates
INSERT INTO email_templates (template_key, template_name, subject_template, body_template, body_html_template, description, available_variables) VALUES
(
    'finding_notification',
    'Security Finding Notification',
    '[SecretSnipe] Security Finding Detected in {{file_path}}',
    'Hello {{owner_name}},

A security finding has been detected in a file you own or manage.

FINDING DETAILS:
================
File: {{file_path}}
Line: {{line_number}}
Secret Type: {{secret_type}}
Severity: {{severity}}
Tool: {{tool_source}}
Category: {{finding_category}}
First Detected: {{first_seen}}

WHAT WAS FOUND:
---------------
{{proof_content}}

REQUIRED ACTION:
----------------
Please review this finding and take appropriate action:
1. If this is a real secret, rotate it immediately and remove from the codebase
2. If this is a false positive, mark it as such in the SecretSnipe dashboard
3. If you need assistance, contact the security team

Dashboard Link: {{dashboard_url}}

You have until {{escalation_date}} to address this finding before it is escalated.

Thank you,
SecretSnipe Security Team',
    NULL,
    'Notification sent to file owners when a finding is detected',
    ARRAY['owner_name', 'owner_email', 'file_path', 'line_number', 'secret_type', 'severity', 'tool_source', 'finding_category', 'first_seen', 'proof_content', 'dashboard_url', 'escalation_date', 'project_name']
),
(
    'escalation_warning',
    'Escalation Warning',
    '[SecretSnipe] URGENT: Unresolved Security Finding - Escalation Imminent',
    'Hello {{owner_name}},

This is a reminder that the following security finding remains unresolved and will be escalated on {{escalation_date}}.

FINDING DETAILS:
================
File: {{file_path}}
Severity: {{severity}}
Days Open: {{days_open}}

Original Notification Sent: {{notification_sent_at}}

Please take immediate action to resolve this finding.

Dashboard Link: {{dashboard_url}}

SecretSnipe Security Team',
    NULL,
    'Warning sent before escalation deadline',
    ARRAY['owner_name', 'owner_email', 'file_path', 'severity', 'escalation_date', 'notification_sent_at', 'days_open', 'dashboard_url']
),
(
    'escalation_notice',
    'Escalation Notice',
    '[SecretSnipe] Security Finding Escalated - {{severity}} Priority',
    'ESCALATION NOTICE

The following security finding has been escalated due to lack of resolution.

FINDING DETAILS:
================
File: {{file_path}}
Severity: {{severity}}
Original Owner: {{owner_name}} ({{owner_email}})
Days Open: {{days_open}}
Original Notification: {{notification_sent_at}}

A Jira ticket has been created: {{jira_ticket_url}}

This requires immediate attention from the security team.

SecretSnipe Security Team',
    NULL,
    'Sent to security team when a finding is escalated',
    ARRAY['owner_name', 'owner_email', 'file_path', 'severity', 'days_open', 'notification_sent_at', 'jira_ticket_url', 'dashboard_url']
)
ON CONFLICT (template_key) DO NOTHING;

-- ============================================================================
-- EMAIL NOTIFICATION LOG
-- ============================================================================

CREATE TABLE IF NOT EXISTS email_notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    template_key VARCHAR(100) REFERENCES email_templates(template_key),
    recipient_email VARCHAR(255) NOT NULL,
    recipient_name VARCHAR(255),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',  -- pending, sent, failed, bounced
    sent_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- PERFORMANCE INDEXES
-- ============================================================================

-- Index for finding category filtering
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(finding_category);

-- Index for parent folder grouping
CREATE INDEX IF NOT EXISTS idx_findings_parent_folder ON findings(parent_folder);

-- Index for owner assignment
CREATE INDEX IF NOT EXISTS idx_findings_owner ON findings(assigned_owner);
CREATE INDEX IF NOT EXISTS idx_findings_owner_email ON findings(owner_email);

-- Index for escalation workflow
CREATE INDEX IF NOT EXISTS idx_findings_escalation ON findings(escalation_status, escalation_date);
CREATE INDEX IF NOT EXISTS idx_findings_notification ON findings(notification_sent_at);

-- Index for file staleness queries
CREATE INDEX IF NOT EXISTS idx_findings_file_accessed ON findings(file_last_accessed);

-- Composite index for dashboard queries
CREATE INDEX IF NOT EXISTS idx_findings_dashboard_query 
    ON findings(resolution_status, finding_category, severity) 
    WHERE resolution_status = 'open';

-- Email notification indexes
CREATE INDEX IF NOT EXISTS idx_email_notifications_finding ON email_notifications(finding_id);
CREATE INDEX IF NOT EXISTS idx_email_notifications_status ON email_notifications(status);

-- ============================================================================
-- MATERIALIZED VIEW FOR DASHBOARD PERFORMANCE
-- ============================================================================

-- Drop if exists to recreate
DROP MATERIALIZED VIEW IF EXISTS mv_findings_summary;

CREATE MATERIALIZED VIEW mv_findings_summary AS
SELECT 
    f.project_id,
    p.name as project_name,
    f.tool_source,
    f.severity,
    f.finding_category,
    f.resolution_status,
    f.parent_folder,
    COUNT(*) as finding_count,
    COUNT(CASE WHEN f.resolution_status = 'open' THEN 1 END) as open_count,
    COUNT(CASE WHEN f.resolution_status = 'false_positive' THEN 1 END) as fp_count,
    MIN(f.first_seen) as earliest_finding,
    MAX(f.first_seen) as latest_finding,
    COUNT(CASE WHEN f.escalation_status = 'pending' THEN 1 END) as pending_escalation
FROM findings f
LEFT JOIN projects p ON f.project_id = p.id
GROUP BY f.project_id, p.name, f.tool_source, f.severity, f.finding_category, 
         f.resolution_status, f.parent_folder;

-- Index on materialized view
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_findings_summary 
    ON mv_findings_summary(project_id, tool_source, severity, finding_category, resolution_status, parent_folder);

-- Function to refresh materialized view
CREATE OR REPLACE FUNCTION refresh_findings_summary()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_findings_summary;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to extract parent folder from file path
CREATE OR REPLACE FUNCTION extract_parent_folder(file_path TEXT, levels INTEGER DEFAULT 2)
RETURNS TEXT AS $$
DECLARE
    parts TEXT[];
    result TEXT;
BEGIN
    IF file_path IS NULL OR file_path = '' THEN
        RETURN '';
    END IF;
    
    parts := string_to_array(file_path, '/');
    
    IF array_length(parts, 1) <= levels + 1 THEN
        -- Not enough levels, return directory part
        RETURN array_to_string(parts[1:array_length(parts, 1)-1], '/');
    ELSE
        -- Return last N folder levels
        RETURN array_to_string(parts[array_length(parts, 1) - levels:array_length(parts, 1) - 1], '/');
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Trigger to auto-populate parent_folder on insert/update
CREATE OR REPLACE FUNCTION update_parent_folder()
RETURNS TRIGGER AS $$
BEGIN
    NEW.parent_folder := extract_parent_folder(NEW.file_path, 2);
    
    -- Also preserve original severity if adjusting
    IF OLD IS NOT NULL AND OLD.severity != NEW.severity AND NEW.original_severity IS NULL THEN
        NEW.original_severity := OLD.severity;
        NEW.severity_adjusted_at := NOW();
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger
DROP TRIGGER IF EXISTS trigger_update_parent_folder ON findings;
CREATE TRIGGER trigger_update_parent_folder
    BEFORE INSERT OR UPDATE ON findings
    FOR EACH ROW
    EXECUTE FUNCTION update_parent_folder();

-- ============================================================================
-- UPDATE EXISTING DATA
-- ============================================================================

-- Populate parent_folder for existing records
UPDATE findings 
SET parent_folder = extract_parent_folder(file_path, 2)
WHERE parent_folder IS NULL;

-- Set original_severity to current severity for existing records
UPDATE findings 
SET original_severity = severity
WHERE original_severity IS NULL;

-- ============================================================================
-- GRANTS (adjust username as needed)
-- ============================================================================

-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO secretsnipe;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO secretsnipe;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO secretsnipe;

COMMENT ON COLUMN findings.finding_category IS 'Category of finding: real_password, real_api_key, finance_data, placeholder, test_data, etc.';
COMMENT ON COLUMN findings.original_severity IS 'Original severity before any manual adjustments';
COMMENT ON COLUMN findings.proof_content IS 'Full context lines around the finding for proof/review';
COMMENT ON COLUMN findings.escalation_status IS 'Escalation workflow status: none, pending, escalated, resolved';
COMMENT ON COLUMN findings.parent_folder IS 'Parent folder path for grouping related files';
COMMENT ON MATERIALIZED VIEW mv_findings_summary IS 'Pre-aggregated summary for fast dashboard queries - refresh periodically';
