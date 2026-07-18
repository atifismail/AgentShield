-- Demo/reference data so the UI and demo attack lab have something to show out of the box.
-- Safe to delete in a real deployment: `DELETE FROM tools; DELETE FROM agents;` before onboarding real agents.
--
-- api_key_hash values are SHA-256 hex digests of documented plaintext demo bearer tokens
-- (see docs/api.md / the demo attack lab), NOT random placeholders:
--   coding-agent-01       -> demo-token-coding-agent-01
--   support-assistant-01  -> demo-token-support-assistant-01
--   retired-agent-01      -> demo-token-retired-agent-01 (agent is DISABLED, token intentionally inert)

INSERT INTO agents (name, description, owner, status, environment, api_key_hash, allowed_tool_groups, created_at, updated_at) VALUES
('coding-agent-01', 'Internal developer coding agent with filesystem, git, and database access', 'platform-team', 'ENABLED', 'DEV', 'c5b68e48db1b3790dd17025b34c1effd475248b65c7f0103766879aa47baa135', 'source-control,filesystem,database', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('support-assistant-01', 'Enterprise assistant connected to SaaS support tools', 'support-team', 'ENABLED', 'PROD', '4cc23ab953a8244a26dacf96f81db935189f68eab2caa734b4bb2409a06d8b7d', 'saas', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('retired-agent-01', 'Decommissioned agent kept for audit history', 'platform-team', 'DISABLED', 'DEV', '1490fb6c324df67e6db1200489f80555be3a99e4fdc15bf74bb5edeb2a88aa5f', 'filesystem', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO tools (name, type, tool_group, endpoint_url, owner, environment, description, schema_json, approved_hash, current_hash, approval_status, last_seen_at, created_at, updated_at) VALUES
('mock-git', 'GIT', 'source-control', '/demo/tools/git', 'platform-team', 'DEV', 'Mock Git tool for commit and push actions', '{"actions":["commit","push","createBranch"]}', 'seed-hash-git-v1', 'seed-hash-git-v1', 'APPROVED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('mock-database', 'DATABASE', 'database', '/demo/tools/database', 'platform-team', 'PROD', 'Mock relational database tool for read/write/delete actions', '{"actions":["query","insert","deleteRecords"]}', 'seed-hash-db-v1', 'seed-hash-db-v1', 'APPROVED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('mock-filesystem', 'FILESYSTEM', 'filesystem', '/demo/tools/filesystem', 'platform-team', 'DEV', 'Mock filesystem tool for read/write file actions', '{"actions":["readFile","writeFile","deleteFile"]}', 'seed-hash-fs-v1', 'seed-hash-fs-v1', 'APPROVED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('mock-saas-crm', 'SAAS', 'saas', '/demo/tools/saas', 'support-team', 'PROD', 'Mock SaaS CRM tool for customer record actions', '{"actions":["getRecord","updateRecord","exportRecords"]}', 'seed-hash-saas-v1', 'seed-hash-saas-v1', 'APPROVED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO policies (name, version, enabled, mode, rule_json, created_by, created_at) VALUES
('default-policy', 1, TRUE, 'ENFORCE', '{"builtin":true,"rules":["deny-disabled-agent","deny-unapproved-tool","deny-schema-drift","deny-prod-destructive-without-approval","require-approval-prod-write","require-approval-external-transfer","deny-secret-external-transfer","deny-prompt-injection-response","deny-tool-outside-allowed-group","deny-oversized-payload"]}', 'system', CURRENT_TIMESTAMP);
