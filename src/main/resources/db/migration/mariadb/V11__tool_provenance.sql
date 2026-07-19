-- See postgresql/V11__tool_provenance.sql for rationale.
ALTER TABLE tools ADD COLUMN source_type VARCHAR(32) NOT NULL DEFAULT 'CUSTOM_HTTP';
UPDATE tools SET source_type = 'MCP' WHERE mcp_server_id IS NOT NULL;
UPDATE tools SET source_type = 'BUILT_IN' WHERE name IN ('mock-git', 'mock-database', 'mock-filesystem', 'mock-saas-crm');

CREATE TABLE tool_provenance (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tool_version_id BIGINT NOT NULL UNIQUE,
    publisher VARCHAR(512),
    checksum_algorithm VARCHAR(32),
    checksum VARCHAR(128),
    verification_mode VARCHAR(32) NOT NULL DEFAULT 'UNVERIFIED',
    signature_bundle LONGTEXT,
    certificate_identity VARCHAR(1024),
    certificate_issuer VARCHAR(1024),
    public_key_ref VARCHAR(512),
    verified_at TIMESTAMP NULL,
    verified_by VARCHAR(255),
    verification_details VARCHAR(2000),
    CONSTRAINT fk_tool_provenance_tool_version FOREIGN KEY (tool_version_id) REFERENCES tool_versions(id)
) ENGINE=InnoDB;

CREATE INDEX idx_tool_provenance_tool_version ON tool_provenance(tool_version_id);
