package com.agentshield.agent;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.List;

public final class AgentDtos {

    private AgentDtos() {
    }

    public record CreateAgentRequest(
            @NotBlank String name,
            String description,
            String owner,
            String environment,
            List<String> allowedToolGroups
    ) {
    }

    public record UpdateAgentRequest(
            String description,
            String owner,
            String environment,
            List<String> allowedToolGroups
    ) {
    }

    public record AgentResponse(
            Long id,
            String name,
            String description,
            String owner,
            AgentStatus status,
            String environment,
            List<String> allowedToolGroups,
            Instant createdAt,
            Instant updatedAt
    ) {
        public static AgentResponse from(Agent agent) {
            return new AgentResponse(agent.getId(), agent.getName(), agent.getDescription(), agent.getOwner(),
                    agent.getStatus(), agent.getEnvironment(), List.copyOf(agent.allowedToolGroupSet()),
                    agent.getCreatedAt(), agent.getUpdatedAt());
        }
    }

    /** Returned exactly once, at creation or rotation time — the hash is all that is ever stored. */
    public record AgentTokenResponse(Long agentId, Long credentialId, String token) {
    }

    public record CreateCredentialRequest(Long validForMinutes) {
    }

    /** Never includes the token — only enough to recognize it (prefix) and its lifecycle state. */
    public record CredentialResponse(
            Long id,
            Long agentId,
            String tokenPrefix,
            CredentialStatus status,
            Instant expiresAt,
            Instant lastUsedAt,
            String createdBy,
            Instant createdAt,
            String revokedBy,
            Instant revokedAt
    ) {
        public static CredentialResponse from(AgentCredential credential) {
            return new CredentialResponse(credential.getId(), credential.getAgent().getId(),
                    credential.getTokenPrefix(), credential.getStatus(), credential.getExpiresAt(),
                    credential.getLastUsedAt(), credential.getCreatedBy(), credential.getCreatedAt(),
                    credential.getRevokedBy(), credential.getRevokedAt());
        }
    }
}
