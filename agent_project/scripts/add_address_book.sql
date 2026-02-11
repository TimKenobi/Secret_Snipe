-- SecretSnipe Agent Database - Address Book and Owner Assignment
-- This adds contact management for finding ownership

-- Address book / contacts table
CREATE TABLE IF NOT EXISTS address_book (
    id SERIAL PRIMARY KEY,
    contact_id UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    department VARCHAR(255),
    title VARCHAR(255),
    phone VARCHAR(50),
    notes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Unique constraint on email
CREATE UNIQUE INDEX IF NOT EXISTS idx_address_book_email ON address_book(email);
CREATE INDEX IF NOT EXISTS idx_address_book_name ON address_book(name);
CREATE INDEX IF NOT EXISTS idx_address_book_active ON address_book(is_active);

-- Add owner fields to findings table
ALTER TABLE agent_findings ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES address_book(contact_id) ON DELETE SET NULL;
ALTER TABLE agent_findings ADD COLUMN IF NOT EXISTS owner_email VARCHAR(255);
ALTER TABLE agent_findings ADD COLUMN IF NOT EXISTS owner_name VARCHAR(255);
ALTER TABLE agent_findings ADD COLUMN IF NOT EXISTS owner_assigned_at TIMESTAMP;
ALTER TABLE agent_findings ADD COLUMN IF NOT EXISTS owner_assigned_by VARCHAR(255);

-- Index for owner lookups
CREATE INDEX IF NOT EXISTS idx_findings_owner_id ON agent_findings(owner_id);
CREATE INDEX IF NOT EXISTS idx_findings_owner_email ON agent_findings(owner_email);

-- Path ownership mapping (assign owners to paths/patterns)
CREATE TABLE IF NOT EXISTS path_ownership (
    id SERIAL PRIMARY KEY,
    path_pattern VARCHAR(500) NOT NULL,  -- Pattern like 'C:\Projects\HR\*' or regex
    is_regex BOOLEAN DEFAULT FALSE,
    owner_id UUID REFERENCES address_book(contact_id) ON DELETE CASCADE,
    description TEXT,
    priority INTEGER DEFAULT 0,  -- Higher priority patterns match first
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_path_ownership_pattern ON path_ownership(path_pattern);
CREATE INDEX IF NOT EXISTS idx_path_ownership_owner ON path_ownership(owner_id);

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_address_book_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_address_book_updated ON address_book;
CREATE TRIGGER trg_address_book_updated
    BEFORE UPDATE ON address_book
    FOR EACH ROW
    EXECUTE FUNCTION update_address_book_timestamp();

-- Function to auto-assign owner based on path patterns
CREATE OR REPLACE FUNCTION auto_assign_finding_owner()
RETURNS TRIGGER AS $$
DECLARE
    matched_owner RECORD;
BEGIN
    -- Only auto-assign if owner not already set
    IF NEW.owner_id IS NULL THEN
        -- Find matching path ownership pattern
        SELECT ab.contact_id, ab.name, ab.email 
        INTO matched_owner
        FROM path_ownership po
        JOIN address_book ab ON po.owner_id = ab.contact_id
        WHERE (
            (NOT po.is_regex AND NEW.file_path LIKE REPLACE(REPLACE(po.path_pattern, '*', '%'), '?', '_'))
            OR 
            (po.is_regex AND NEW.file_path ~ po.path_pattern)
        )
        AND ab.is_active = TRUE
        ORDER BY po.priority DESC, LENGTH(po.path_pattern) DESC
        LIMIT 1;
        
        IF matched_owner IS NOT NULL THEN
            NEW.owner_id = matched_owner.contact_id;
            NEW.owner_name = matched_owner.name;
            NEW.owner_email = matched_owner.email;
            NEW.owner_assigned_at = CURRENT_TIMESTAMP;
            NEW.owner_assigned_by = 'auto';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auto_assign_owner ON agent_findings;
CREATE TRIGGER trg_auto_assign_owner
    BEFORE INSERT ON agent_findings
    FOR EACH ROW
    EXECUTE FUNCTION auto_assign_finding_owner();

COMMENT ON TABLE address_book IS 'Contact information for finding owners';
COMMENT ON TABLE path_ownership IS 'Maps file path patterns to responsible owners';
