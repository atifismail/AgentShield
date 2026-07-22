-- See postgresql/V19__soc_validation.sql for rationale, including the MITRE mapping notes.
ALTER TABLE detection_rules ADD COLUMN mitre_attack_id VARCHAR(32);

UPDATE detection_rules SET mitre_attack_id = 'T1195' WHERE code = 'deny-schema-drift';
UPDATE detection_rules SET mitre_attack_id = 'T1485' WHERE code = 'deny-prod-destructive-without-approval';
UPDATE detection_rules SET mitre_attack_id = 'T1552' WHERE code = 'deny-secret-external-transfer';
UPDATE detection_rules SET mitre_attack_id = 'ATLAS:AML.T0051' WHERE code = 'deny-prompt-injection-response';
UPDATE detection_rules SET mitre_attack_id = 'T1078' WHERE code = 'deny-disabled-agent';
UPDATE detection_rules SET mitre_attack_id = 'T1567' WHERE code = 'require-approval-external-transfer';
UPDATE detection_rules SET mitre_attack_id = 'T1552' WHERE code = 'deny-dlp-block';
UPDATE detection_rules SET mitre_attack_id = 'T1552' WHERE code = 'require-approval-dlp-finding';

INSERT INTO detection_rules (code, name, category, description, source, reference_id, mitre_attack_id, created_at) VALUES
('mcp-oauth-token-rejected', 'MCP OAuth token rejected (wrong audience/issuer/expired/scope)', 'IDENTITY_PRIVILEGE_ABUSE', 'An OAuth 2.1 access token for an MCP server failed audience, issuer, expiry, or scope validation and was discarded, never cached.', 'MCP_OAUTH', 'mcp.oauth_token_rejected', 'T1528', CURRENT_TIMESTAMP),
('codetrust-blocked', 'AI-assisted code assessment blocked on a HIGH/CRITICAL finding', 'SUPPLY_CHAIN_RISK', 'A submitted code assessment (CLI/CI scan result) contained a HIGH or CRITICAL finding (e.g. a committed secret) and was blocked pending human review.', 'CODE_TRUST', 'codetrust.blocked', 'T1195.001', CURRENT_TIMESTAMP);

CREATE TABLE validation_runs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    triggered_by VARCHAR(255),
    matched_count INT NOT NULL,
    missed_count INT NOT NULL,
    unexpected_count INT NOT NULL,
    matched_scenarios_json VARCHAR(4000),
    missed_scenarios_json VARCHAR(4000),
    unexpected_alerts_json VARCHAR(4000),
    created_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_validation_runs_created_at ON validation_runs(created_at);
