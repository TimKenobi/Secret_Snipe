-- SecretSnipe Schema Migration v3
-- Adds proper resolution status support and new columns
-- Run with: docker exec -i secretsnipe-postgres psql -U secretsnipe -d secretsnipe < scripts/schema_migration_v3.sql

-- ============================================================================
-- ENHANCED RESOLUTION STATUS COLUMNS
-- ============================================================================

-- Add columns for 'reviewed' status tracking
ALTER TABLE findings ADD COLUMN IF NOT EXISTS review_reason TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reviewed_by VARCHAR(255);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP WITH TIME ZONE;

-- Add columns for 'accepted_risk' status tracking  
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_accepted_reason TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_accepted_by VARCHAR(255);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_accepted_at TIMESTAMP WITH TIME ZONE;

-- Add column for last file access time (atime)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS file_last_accessed TIMESTAMP WITH TIME ZONE;

-- ============================================================================
-- RESOLUTION STATUS LOOKUP TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS resolution_statuses (
    id SERIAL PRIMARY KEY,
    status_key VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    color_code VARCHAR(20),
    is_resolved BOOLEAN DEFAULT false,  -- Whether this status counts as "resolved"
    excludes_from_counts BOOLEAN DEFAULT false,  -- Whether to exclude from open counts
    sort_order INTEGER DEFAULT 100,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default resolution statuses
INSERT INTO resolution_statuses (status_key, display_name, description, icon, color_code, is_resolved, excludes_from_counts, sort_order) VALUES
    ('open', 'Open', 'New finding that needs review', '🔴', '#ef4444', false, false, 10),
    ('reviewed', 'Reviewed/Remediated', 'Finding reviewed and addressed (secret rotated/removed)', '✅', '#22c55e', true, true, 20),
    ('false_positive', 'False Positive', 'Not a real secret - detection error', '🚫', '#f59e0b', true, true, 30),
    ('accepted_risk', 'Accepted Risk', 'Real secret but risk is acknowledged and accepted', '⚠️', '#8b5cf6', true, true, 40),
    ('resolved', 'Resolved (Legacy)', 'Legacy resolved status', '✓', '#6b7280', true, true, 100)
ON CONFLICT (status_key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color_code = EXCLUDED.color_code;

-- ============================================================================
-- CUSTOM CATEGORIES TABLE ENHANCEMENT
-- ============================================================================

-- Add is_custom column to distinguish user-created categories
ALTER TABLE finding_categories ADD COLUMN IF NOT EXISTS is_custom BOOLEAN DEFAULT false;

-- Update existing categories to not be custom (they're system defaults)
UPDATE finding_categories SET is_custom = false WHERE is_custom IS NULL;

-- ============================================================================
-- INDEXES FOR NEW COLUMNS
-- ============================================================================

-- Index for reviewed status queries
CREATE INDEX IF NOT EXISTS idx_findings_reviewed ON findings(reviewed_at) WHERE resolution_status = 'reviewed';

-- Index for accepted risk queries  
CREATE INDEX IF NOT EXISTS idx_findings_accepted_risk ON findings(risk_accepted_at) WHERE resolution_status = 'accepted_risk';

-- Index for file access time queries (for finding stale files)
CREATE INDEX IF NOT EXISTS idx_findings_file_accessed ON findings(file_last_accessed);

-- ============================================================================
-- HELPER VIEWS
-- ============================================================================

-- View for resolution status summary
CREATE OR REPLACE VIEW v_resolution_summary AS
SELECT 
    resolution_status,
    rs.display_name,
    rs.icon,
    rs.color_code,
    COUNT(*) as count
FROM findings f
LEFT JOIN resolution_statuses rs ON f.resolution_status = rs.status_key
GROUP BY f.resolution_status, rs.display_name, rs.icon, rs.color_code
ORDER BY rs.sort_order;

-- ============================================================================
-- ADD COMMENTS
-- ============================================================================

COMMENT ON COLUMN findings.review_reason IS 'Reason/notes when finding is marked as reviewed';
COMMENT ON COLUMN findings.reviewed_by IS 'User who reviewed the finding';
COMMENT ON COLUMN findings.reviewed_at IS 'Timestamp when finding was reviewed';
COMMENT ON COLUMN findings.risk_accepted_reason IS 'Justification for accepting the risk';
COMMENT ON COLUMN findings.risk_accepted_by IS 'User who accepted the risk';
COMMENT ON COLUMN findings.risk_accepted_at IS 'Timestamp when risk was accepted';
COMMENT ON COLUMN findings.file_last_accessed IS 'Last access time of the file (atime from filesystem)';

-- Refresh materialized view
SELECT refresh_findings_summary();

-- Report completion
DO $$
BEGIN
    RAISE NOTICE 'Schema migration v3 completed successfully!';
    RAISE NOTICE 'New resolution statuses: open, reviewed, false_positive, accepted_risk';
    RAISE NOTICE 'New columns: review_reason, reviewed_by, reviewed_at, risk_accepted_reason, risk_accepted_by, risk_accepted_at, file_last_accessed';
END $$;
