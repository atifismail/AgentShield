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
            String envRef,
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
                    s.getOwner(), s.getEnvironment(), s.getToolGroup(), s.getDiscoveredToolsHash(),
                    s.getLastDiscoveredAt(), s.getCreatedAt(), s.getAuthMode(), s.getOauthIssuer(),
                    s.getOauthResource(), s.getOauthClientId(), s.getOauthClientSecretRef(), s.getOauthScopes());
        }
    }

    public record DiscoveryResponse(List<String> discoveredOrUpdatedTools, List<String> removedTools) {
    }
}
