package com.agentshield.governance;

import com.agentshield.common.ActionCategory;
import com.agentshield.common.ApprovalStatus;
import com.agentshield.common.PolicyDecisionType;
import java.time.Instant;
import java.util.List;

public final class EvidenceExportDtos {

    private EvidenceExportDtos() {
    }

    public record ToolCallEvent(
            String schemaVersion,
            Long id,
            String correlationId,
            Long agentId,
            String agentName,
            Long toolId,
            String toolName,
            ActionCategory actionCategory,
            String targetEnvironment,
            String status,
            Instant createdAt
    ) {
    }

    public record PolicyDecisionEvent(
            String schemaVersion,
            Long id,
            Long gatewayRequestId,
            PolicyDecisionType decision,
            String ruleId,
            String policyVersion,
            String redactedReason,
            Integer riskScore,
            String riskLevel,
            Instant createdAt
    ) {
    }

    public record ApprovalEvent(
            String schemaVersion,
            Long id,
            Long gatewayRequestId,
            ApprovalStatus status,
            Long approvalProfileId,
            String assignedRole,
            String requestedBy,
            String decidedBy,
            Instant createdAt,
            Instant decidedAt
    ) {
    }

    public record EvaluationRunSummary(
            String schemaVersion,
            Long id,
            Long suiteId,
            int suiteVersion,
            String policyConfigFingerprint,
            String triggeredBy,
            Instant startedAt,
            Instant completedAt,
            int totalCases,
            int passedCases,
            int failedCases,
            int errorCases
    ) {
    }

    public record EvidenceBundle(
            String schemaVersion,
            String exporterVersion,
            Instant generatedAt,
            Instant queryFrom,
            Instant queryTo,
            String redactionPolicyVersion,
            List<ToolCallEvent> toolCallEvents,
            List<PolicyDecisionEvent> policyDecisionEvents,
            List<ApprovalEvent> approvalEvents,
            List<EvaluationRunSummary> evaluationRunSummaries
    ) {
    }
}
