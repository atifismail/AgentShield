package com.agentshield.mcp;

/** How AgentShield authenticates itself to an MCP server (design-mcp-authorization.md §4). */
public enum McpAuthMode {
    /** No authentication to the MCP server — today's only behavior. */
    NONE,
    /** HTTP transport, OAuth 2.1 client_credentials against the server's authorization server. */
    OAUTH2,
    /** stdio transport (not yet implemented): credentials brokered via an approved env var allowlist. */
    STDIO_ENV
}
