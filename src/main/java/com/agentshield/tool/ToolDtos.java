package com.agentshield.tool;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public final class ToolDtos {

    private ToolDtos() {
    }

    public record RegisterToolRequest(
            @NotBlank String name,
            @NotNull ToolType type,
            String toolGroup,
            String endpointUrl,
            String owner,
            String environment,
            String description,
            String schemaJson
    ) {
    }

    public record UpdateToolFingerprintRequest(
            String description,
            String schemaJson
    ) {
    }

    public record ToolResponse(
            Long id,
            String name,
            ToolType type,
            String toolGroup,
            String endpointUrl,
            String owner,
            String environment,
            String description,
            String approvedHash,
            String currentHash,
            ToolApprovalStatus approvalStatus,
            boolean drifted,
            Instant lastSeenAt,
            Instant createdAt,
            Instant updatedAt
    ) {
        public static ToolResponse from(Tool tool) {
            return new ToolResponse(tool.getId(), tool.getName(), tool.getType(), tool.getToolGroup(),
                    tool.getEndpointUrl(), tool.getOwner(), tool.getEnvironment(), tool.getDescription(),
                    tool.getApprovedHash(), tool.getCurrentHash(), tool.getApprovalStatus(), tool.hasDrift(),
                    tool.getLastSeenAt(), tool.getCreatedAt(), tool.getUpdatedAt());
        }
    }

    public record ToolVersionResponse(
            Long id,
            Long toolId,
            String description,
            String hash,
            Instant detectedAt,
            String approvedBy,
            Instant approvedAt,
            ToolVersionStatus status
    ) {
        public static ToolVersionResponse from(ToolVersion version) {
            return new ToolVersionResponse(version.getId(), version.getTool().getId(), version.getDescription(),
                    version.getHash(), version.getDetectedAt(), version.getApprovedBy(), version.getApprovedAt(),
                    version.getStatus());
        }
    }

    public record ApprovalDecisionRequest(@NotBlank String decidedBy) {
    }
}
