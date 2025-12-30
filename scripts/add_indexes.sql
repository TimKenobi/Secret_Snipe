-- Add new composite indexes for improved dashboard performance
-- Run this script to optimize the existing database

-- These indexes improve common dashboard queries
CREATE INDEX IF NOT EXISTS idx_findings_resolution_first_seen ON findings(resolution_status, first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tool_resolution ON findings(tool_source, resolution_status);
CREATE INDEX IF NOT EXISTS idx_findings_severity_resolution ON findings(severity, resolution_status);
CREATE INDEX IF NOT EXISTS idx_findings_file_resolution ON findings(file_path, resolution_status);
CREATE INDEX IF NOT EXISTS idx_findings_secret_type ON findings(secret_type);

-- Analyze tables to update statistics for query planner
ANALYZE findings;
ANALYZE projects;
ANALYZE scan_sessions;

-- Show index statistics
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan as times_used,
    idx_tup_read as rows_read,
    idx_tup_fetch as rows_fetched
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC;
