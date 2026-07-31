-- Explicit Entitlements release, work package 1 (agentshield_policy_evidence_execution_plan
-- section 6). Entirely additive: description_hash/input_schema_hash/output_schema_hash are
-- left NULL for every existing tool rather than backfilled from the combined approved_hash/
-- current_hash — a null individual hash means "legacy/unavailable", never "confirmed identical".
-- risk_tier/default_action default to the safest values (UNCLASSIFIED/REVIEW) for every existing
-- tool. approved_hash and current_hash are untouched and keep governing drift exactly as before.
ALTER TABLE tools ADD COLUMN description_hash VARCHAR(128);
ALTER TABLE tools ADD COLUMN input_schema_hash VARCHAR(128);
ALTER TABLE tools ADD COLUMN output_schema_hash VARCHAR(128);
ALTER TABLE tools ADD COLUMN output_schema_json TEXT;
ALTER TABLE tools ADD COLUMN risk_tier VARCHAR(32) NOT NULL DEFAULT 'UNCLASSIFIED';
ALTER TABLE tools ADD COLUMN default_action VARCHAR(32) NOT NULL DEFAULT 'REVIEW';
ALTER TABLE tools ADD COLUMN fingerprint_format_version SMALLINT NOT NULL DEFAULT 1;

-- tool_versions gets the same field-level hash columns so the field that actually changed
-- (description vs input schema vs output schema) can be reconstructed from history, the same
-- way the existing combined `hash` column already snapshots the legacy fingerprint per version.
ALTER TABLE tool_versions ADD COLUMN description_hash VARCHAR(128);
ALTER TABLE tool_versions ADD COLUMN input_schema_hash VARCHAR(128);
ALTER TABLE tool_versions ADD COLUMN output_schema_hash VARCHAR(128);
ALTER TABLE tool_versions ADD COLUMN output_schema_json TEXT;
