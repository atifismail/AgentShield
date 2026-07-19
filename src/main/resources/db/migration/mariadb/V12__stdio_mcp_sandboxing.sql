-- Renames the previously-unimplemented single-value env_ref column into a comma-separated
-- allowlist of environment variable NAMES for stdio MCP subprocess spawning
-- (design-stdio-sse-mcp-transport-and-sandboxing.md §5.2, §8). Safe rename: the column has never
-- been read/written by application code (stdio transport itself was not implemented until now).
ALTER TABLE mcp_servers RENAME COLUMN env_ref TO stdio_env_allowlist;
