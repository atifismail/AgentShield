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
    public record AgentTokenResponse(Long agentId, String token) {
    }
}
