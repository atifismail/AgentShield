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
