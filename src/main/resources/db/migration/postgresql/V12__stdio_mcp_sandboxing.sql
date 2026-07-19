-- See mariadb/V12__stdio_mcp_sandboxing.sql for rationale.
ALTER TABLE mcp_servers RENAME COLUMN env_ref TO stdio_env_allowlist;
