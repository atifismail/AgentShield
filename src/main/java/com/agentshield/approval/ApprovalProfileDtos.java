package com.agentshield.approval;

import com.agentshield.common.ActionCategory;
import com.agentshield.security.UserRole;
import com.agentshield.tool.ToolRiskTier;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public final class ApprovalProfileDtos {

    private ApprovalProfileDtos() {
    }

    public record CreateApprovalProfileRequest(
            @NotBlank String name,
            String description,
            @NotNull Integer priority,
            Long agentId,
            Long toolId,
            String toolGroup,
            ActionCategory actionCategory,
            String targetEnvironment,
            ToolRiskTier riskTier,
            @NotNull UserRole targetRole,
            Integer expirationMinutes
    ) {
    }

    public record ApprovalProfileResponse(
            Long id,
            String name,
            String description,
            int priority,
            boolean enabled,
            Long agentId,
            Long toolId,
            String toolGroup,
            ActionCategory actionCategory,
            String targetEnvironment,
            ToolRiskTier riskTier,
            UserRole targetRole,
            Integer expirationMinutes,
            String createdBy,
            Instant createdAt,
            Instant updatedAt
    ) {
        public static ApprovalProfileResponse from(ApprovalProfile profile) {
            return new ApprovalProfileResponse(profile.getId(), profile.getName(), profile.getDescription(),
                    profile.getPriority(), profile.isEnabled(), profile.getAgentId(), profile.getToolId(),
                    profile.getToolGroup(), profile.getActionCategory(), profile.getTargetEnvironment(),
                    profile.getRiskTier(), profile.getTargetRole(), profile.getExpirationMinutes(),
                    profile.getCreatedBy(), profile.getCreatedAt(), profile.getUpdatedAt());
        }
    }
}
