package com.agentshield.mcp;

import com.agentshield.common.ActionCategory;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public final class McpConsentDtos {

    private McpConsentDtos() {
    }

    public record CreateConsentRequest(
            @NotNull Long agentId,
            @NotNull Long mcpServerId,
            String toolName,
            ActionCategory actionCategory,
            Instant expiresAt
    ) {
    }

    public record ConsentResponse(
            Long id,
            Long agentId,
            String agentName,
            Long mcpServerId,
            String mcpServerName,
            String toolName,
            ActionCategory actionCategory,
            ConsentStatus status,
            String grantedBy,
            Instant grantedAt,
            Instant expiresAt,
            String revokedBy,
            Instant revokedAt
    ) {
        public static ConsentResponse from(McpConsent c) {
            return new ConsentResponse(c.getId(), c.getAgent().getId(), c.getAgent().getName(),
                    c.getMcpServer().getId(), c.getMcpServer().getName(), c.getToolName(), c.getActionCategory(),
                    c.getStatus(), c.getGrantedBy(), c.getGrantedAt(), c.getExpiresAt(), c.getRevokedBy(),
                    c.getRevokedAt());
        }
    }
}
