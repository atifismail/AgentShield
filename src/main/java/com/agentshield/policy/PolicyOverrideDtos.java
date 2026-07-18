package com.agentshield.policy;

import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public final class PolicyOverrideDtos {

    private PolicyOverrideDtos() {
    }

    public record CreateOverrideRequest(
            ActionCategory actionCategory,
            String targetEnvironment,
            String toolGroup,
            String agentName,
            @NotNull PolicyDecisionType decision,
            @NotBlank String reason,
            Integer priority
    ) {
    }

    public record OverrideResponse(
            Long id,
            boolean enabled,
            ActionCategory actionCategory,
            String targetEnvironment,
            String toolGroup,
            String agentName,
            PolicyDecisionType decision,
            String reason,
            int priority,
            String createdBy,
            Instant createdAt
    ) {
        public static OverrideResponse from(PolicyOverride o) {
            return new OverrideResponse(o.getId(), o.isEnabled(), o.getActionCategory(), o.getTargetEnvironment(),
                    o.getToolGroup(), o.getAgentName(), o.getDecision(), o.getReason(), o.getPriority(),
                    o.getCreatedBy(), o.getCreatedAt());
        }
    }
}
