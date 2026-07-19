package com.agentshield.mcp;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.List;

public final class McpDtos {

    private McpDtos() {
    }

    public record RegisterMcpServerRequest(
            @NotBlank String name,
            @NotNull McpTransportType transportType,
            String endpointUrl,
            String command,
            String args,
            /**
             * STDIO transport only: comma-separated environment variable NAMES to allow through to
             * the subprocess, never values. Empty by default — nothing is passed through
             * automatically. HOME/USERPROFILE may be listed but are sensitive; see
             * docs/operations.md.
             */
            String stdioEnvAllowlist,
            String owner,
            String environment,
            String toolGroup
    ) {
    }

    /** design-mcp-authorization.md §9 — set separately from registration, ADMIN only. */
    public record UpdateMcpAuthRequest(
            @NotNull McpAuthMode authMode,
            String oauthIssuer,
            String oauthResource,
            String oauthTokenEndpoint,
            String oauthClientId,
            String oauthClientSecretRef,
            String oauthScopes
    ) {
    }

    public record McpServerResponse(
            Long id,
            String name,
            McpTransportType transportType,
            String endpointUrl,
            String command,
            String args,
            String stdioEnvAllowlist,
            String owner,
            String environment,
            String toolGroup,
            String discoveredToolsHash,
            Instant lastDiscoveredAt,
            Instant createdAt,
            McpAuthMode authMode,
            String oauthIssuer,
            String oauthResource,
            String oauthClientId,
            String oauthClientSecretRef,
            String oauthScopes
    ) {
        public static McpServerResponse from(McpServer s) {
            return new McpServerResponse(s.getId(), s.getName(), s.getTransportType(), s.getEndpointUrl(),
                    s.getCommand(), s.getArgs(), s.getStdioEnvAllowlist(), s.getOwner(), s.getEnvironment(),
                    s.getToolGroup(), s.getDiscoveredToolsHash(), s.getLastDiscoveredAt(), s.getCreatedAt(),
                    s.getAuthMode(), s.getOauthIssuer(), s.getOauthResource(), s.getOauthClientId(),
                    s.getOauthClientSecretRef(), s.getOauthScopes());
        }
    }

    /** Runtime (in-memory, not persisted) status of a STDIO transport server's managed subprocess. */
    public record McpTransportStatusResponse(boolean running, Long pid, Instant startedAt, Instant lastActivityAt) {
    }

    public record DiscoveryResponse(List<String> discoveredOrUpdatedTools, List<String> removedTools) {
    }
}
