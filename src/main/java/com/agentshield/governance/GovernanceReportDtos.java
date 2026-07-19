package com.agentshield.governance;

import java.time.Instant;
import java.util.List;

/**
 * Evidence export for a date range, mapped to NIST AI RMF's govern/map/measure/manage functions
 * (improvement_plan.md P2 "AI RMF Governance Mapping"). This is a read-only snapshot assembled
 * from existing operational records — it introduces no new tracked state of its own.
 */
public final class GovernanceReportDtos {

    private GovernanceReportDtos() {
    }

    public record GovernanceReport(
            Instant from,
            Instant to,
            Instant generatedAt,
            RegisteredAgents registeredAgents,
            ApprovedTools approvedTools,
            DeniedActions deniedActions,
            ApprovalRecords approvalRecords,
            DriftEvents driftEvents,
            Incidents incidents,
            PolicyVersions policyVersions
    ) {
    }

    /** RMF Govern: who is authorized to act as an agent in this system, and under what identity. */
    public record RegisteredAgents(long totalCount, List<AgentSummary> agents) {
    }

    public record AgentSummary(String name, String status, String owner, String allowedToolGroups, Instant createdAt) {
    }

    /** RMF Map: which tools are in scope and their current trust/approval status. */
    public record ApprovedTools(long totalCount, List<ToolSummary> tools) {
    }

    public record ToolSummary(String name, String type, String toolGroup, String sourceType,
            String approvalStatus, Instant createdAt) {
    }

    /** RMF Measure: actions the policy engine actually blocked in the period. */
    public record DeniedActions(long count, List<DeniedActionSummary> actions) {
    }

    public record DeniedActionSummary(Long gatewayRequestId, String agentName, String toolName,
            String actionCategory, String reason, String riskLevel, int riskScore, Instant createdAt) {
    }

    /** RMF Manage: human decisions made on APPROVAL_REQUIRED actions in the period. */
    public record ApprovalRecords(long count, long approvedCount, long rejectedCount, long expiredCount,
            List<ApprovalSummary> approvals) {
    }

    public record ApprovalSummary(Long id, Long gatewayRequestId, String status, String requestedBy,
            String approvedBy, String rejectedBy, Instant createdAt) {
    }

    /** RMF Measure: tool fingerprint changes detected in the period, resolved or not. */
    public record DriftEvents(long count, List<DriftEventSummary> events) {
    }

    public record DriftEventSummary(String toolName, Long toolVersionId, String status, Instant detectedAt) {
    }

    /** RMF Manage: security incidents opened in the period. */
    public record Incidents(long count, List<IncidentSummary> incidents) {
    }

    public record IncidentSummary(Long id, String title, String severity, String status, Instant createdAt) {
    }

    /** RMF Govern: the policy versions in force, independent of the requested date range. */
    public record PolicyVersions(List<PolicyVersionSummary> policies) {
    }

    public record PolicyVersionSummary(String name, int version, boolean enabled, String mode, String createdBy,
            Instant createdAt) {
    }
}
