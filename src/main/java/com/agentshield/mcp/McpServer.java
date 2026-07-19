package com.agentshield.mcp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A registered MCP server. All three {@link McpTransportType} values are invokable per
 * design-stdio-sse-mcp-transport-and-sandboxing.md: {@code HTTP} is plain request/response;
 * {@code SSE} is a persistent Server-Sent-Events connection (same SSRF policy as HTTP, no
 * subprocess/filesystem/env concerns); {@code STDIO} spawns a locally-sandboxed subprocess and is
 * gated behind {@code agentshield.stdio.enabled} (off by default) — the only transport with a
 * feature flag, since it's the only one with local-code-execution risk.
 */
@Entity
@Table(name = "mcp_servers")
@Getter
@Setter
@NoArgsConstructor
public class McpServer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "transport_type", nullable = false, length = 32)
    private McpTransportType transportType;

    @Column(name = "endpoint_url", length = 1024)
    private String endpointUrl;

    /** STDIO transport only (not yet implemented): the command to launch the server process. */
    @Column(length = 1024)
    private String command;

    /** STDIO transport only (not yet implemented): space-separated process arguments. */
    @Column(length = 2000)
    private String args;

    /**
     * STDIO transport only: comma-separated environment variable NAMES (never values) to copy
     * into the spawned subprocess's environment, resolved from AgentShield's own process
     * environment at spawn time. Empty/null by default — nothing is passed through automatically,
     * not even PATH/HOME (design-stdio-sse-mcp-transport-and-sandboxing.md §5.2). HOME/USERPROFILE
     * require the same explicit listing as any other name and are documented as sensitive.
     */
    @Column(name = "stdio_env_allowlist")
    private String stdioEnvAllowlist;

    /** How AgentShield authenticates itself to this server (design-mcp-authorization.md §4). */
    @Enumerated(EnumType.STRING)
    @Column(name = "auth_mode", nullable = false, length = 32)
    private McpAuthMode authMode = McpAuthMode.NONE;

    /** OAuth 2.1 only: expected `iss` claim / the authorization server's issuer URL. */
    @Column(name = "oauth_issuer", length = 1024)
    private String oauthIssuer;

    /** OAuth 2.1 only: canonical resource URI (RFC 8707) — also the expected `aud` claim. */
    @Column(name = "oauth_resource", length = 1024)
    private String oauthResource;

    /** OAuth 2.1 only: resolved via discovery at registration time and cached here. */
    @Column(name = "oauth_token_endpoint", length = 1024)
    private String oauthTokenEndpoint;

    @Column(name = "oauth_client_id", length = 512)
    private String oauthClientId;

    /** A reference name only — the plaintext secret is never stored here (design §6.4). */
    @Column(name = "oauth_client_secret_ref", length = 512)
    private String oauthClientSecretRef;

    /** Space-separated scopes requested at token time. */
    @Column(name = "oauth_scopes", length = 1024)
    private String oauthScopes;

    private String owner;

    private String environment;

    @Column(name = "tool_group", nullable = false, length = 128)
    private String toolGroup = "default";

    /** Fingerprint of the last discovery's tool set (names+descriptions+schemas), for server-level drift visibility. */
    @Column(name = "discovered_tools_hash", length = 128)
    private String discoveredToolsHash;

    @Column(name = "last_discovered_at")
    private Instant lastDiscoveredAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
