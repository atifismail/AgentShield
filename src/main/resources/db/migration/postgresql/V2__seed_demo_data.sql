-- Baseline default-policy metadata record — applies to every deployment, not just demo/local.
-- The rules that actually run are the fixed Java rules in PolicyEngine; this row is the
-- versioned record of that baseline (PROJECT_PLAN.md section 2, docs/policy-guide.md).
--
-- Demo agents/tools/tokens are NOT seeded here — see com.agentshield.demo.DemoDataSeeder,
-- which only runs when the "demo" Spring profile is active (improvement_plan.md #5).

INSERT INTO policies (name, version, enabled, mode, rule_json, created_by, created_at) VALUES
('default-policy', 1, TRUE, 'ENFORCE', '{"builtin":true,"rules":["deny-disabled-agent","deny-unapproved-tool","deny-schema-drift","deny-prod-destructive-without-approval","require-approval-prod-write","require-approval-external-transfer","deny-secret-external-transfer","deny-prompt-injection-response","deny-tool-outside-allowed-group","deny-oversized-payload"]}', 'system', CURRENT_TIMESTAMP);
