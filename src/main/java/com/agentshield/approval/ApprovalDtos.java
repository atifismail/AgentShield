package com.agentshield.approval;

import com.agentshield.common.ApprovalStatus;
import com.agentshield.gateway.GatewayDtos.InvokeResponse;
import com.agentshield.security.UserRole;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;

public final class ApprovalDtos {

    private ApprovalDtos() {
    }

    public record ApprovalDecisionRequest(@NotBlank String decidedBy) {
    }

    public record ApprovalResponse(
            Long id,
            Long gatewayRequestId,
            String correlationId,
            String requestedBy,
            String assignedTo,
            ApprovalStatus status,
            String reason,
            String approvedBy,
            Instant approvedAt,
            String rejectedBy,
            Instant rejectedAt,
            Instant expiresAt,
            Instant createdAt,
            InvokeResponse executionResult,
            Long approvalProfileId,
            UserRole assignedRole
    ) {
        public static ApprovalResponse from(ApprovalRequest approval) {
            return from(approval, null);
        }

        public static ApprovalResponse from(ApprovalRequest approval, InvokeResponse executionResult) {
            return new ApprovalResponse(
                    approval.getId(),
                    approval.getGatewayRequest().getId(),
                    approval.getGatewayRequest().getCorrelationId(),
                    approval.getRequestedBy(),
                    approval.getAssignedTo(),
                    approval.getStatus(),
                    approval.getReason(),
                    approval.getApprovedBy(),
                    approval.getApprovedAt(),
                    approval.getRejectedBy(),
                    approval.getRejectedAt(),
                    approval.getExpiresAt(),
                    approval.getCreatedAt(),
                    executionResult,
                    approval.getApprovalProfileId(),
                    approval.getAssignedRole());
        }
    }
}
