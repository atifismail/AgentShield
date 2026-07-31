-- See postgresql/V20__tool_fingerprint_and_risk_fields.sql for rationale.
ALTER TABLE tools ADD COLUMN description_hash VARCHAR(128);
ALTER TABLE tools ADD COLUMN input_schema_hash VARCHAR(128);
ALTER TABLE tools ADD COLUMN output_schema_hash VARCHAR(128);
ALTER TABLE tools ADD COLUMN output_schema_json LONGTEXT;
ALTER TABLE tools ADD COLUMN risk_tier VARCHAR(32) NOT NULL DEFAULT 'UNCLASSIFIED';
ALTER TABLE tools ADD COLUMN default_action VARCHAR(32) NOT NULL DEFAULT 'REVIEW';
ALTER TABLE tools ADD COLUMN fingerprint_format_version SMALLINT NOT NULL DEFAULT 1;

ALTER TABLE tool_versions ADD COLUMN description_hash VARCHAR(128);
ALTER TABLE tool_versions ADD COLUMN input_schema_hash VARCHAR(128);
ALTER TABLE tool_versions ADD COLUMN output_schema_hash VARCHAR(128);
ALTER TABLE tool_versions ADD COLUMN output_schema_json LONGTEXT;
