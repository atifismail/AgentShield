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
 * A registered MCP server. Only {@link McpTransportType#HTTP} is actually invokable today —
 * {@code SSE} and {@code STDIO} can be registered (the schema supports them, per
 * improvement_plan.md #6) but discovery/invocation for them isn't implemented yet and fails
 * clearly rather than pretending to work.
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

    /** STDIO transport only (not yet implemented): a reference name for env vars to inject — never a raw secret value. */
    @Column(name = "env_ref")
    private String envRef;

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
