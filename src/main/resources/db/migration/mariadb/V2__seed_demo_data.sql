-- See postgresql/V2__seed_demo_data.sql for rationale.
INSERT INTO policies (name, version, enabled, mode, rule_json, created_by, created_at) VALUES
('default-policy', 1, TRUE, 'ENFORCE', '{"builtin":true,"rules":["deny-disabled-agent","deny-unapproved-tool","deny-schema-drift","deny-prod-destructive-without-approval","require-approval-prod-write","require-approval-external-transfer","deny-secret-external-transfer","deny-prompt-injection-response","deny-tool-outside-allowed-group","deny-oversized-payload"]}', 'system', CURRENT_TIMESTAMP);
