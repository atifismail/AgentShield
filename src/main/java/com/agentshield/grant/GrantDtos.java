package com.agentshield.grant;

import com.agentshield.common.ActionCategory;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public final class GrantDtos {

    private GrantDtos() {
    }

    public record CreateGrantRequest(
            @NotNull Long toolId,
            ActionCategory actionCategory,
            String targetEnvironment,
            String resourcePathPattern,
            String requiredTokenScope,
            Instant notBefore,
            Instant expiresAt,
            String reason
    ) {
    }

    public record RevokeGrantRequest(String reason) {
    }

    public record GrantResponse(
            Long id,
            Long agentId,
            Long toolId,
            String toolName,
            GrantStatus status,
            ActionCategory actionCategory,
            String targetEnvironment,
            String resourcePathPattern,
            String requiredTokenScope,
            Instant notBefore,
            Instant expiresAt,
            String createdBy,
            String revokedBy,
            Instant revokedAt,
            String reason,
            Instant createdAt,
            Instant updatedAt
    ) {
        public static GrantResponse from(AgentToolGrant grant, String toolName) {
            return new GrantResponse(grant.getId(), grant.getAgentId(), grant.getToolId(), toolName,
                    grant.getStatus(), grant.getActionCategory(), grant.getTargetEnvironment(),
                    grant.getResourcePathPattern(), grant.getRequiredTokenScope(), grant.getNotBefore(),
                    grant.getExpiresAt(), grant.getCreatedBy(), grant.getRevokedBy(), grant.getRevokedAt(),
                    grant.getReason(), grant.getCreatedAt(), grant.getUpdatedAt());
        }
    }
}
