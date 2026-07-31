package com.agentshield.governance;

import com.agentshield.approval.ApprovalRequest;
import com.agentshield.approval.ApprovalRequestRepository;
import com.agentshield.common.ValidationException;
import com.agentshield.evaluation.EvaluationRun;
import com.agentshield.evaluation.EvaluationRunRepository;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.governance.EvidenceExportDtos.ApprovalEvent;
import com.agentshield.governance.EvidenceExportDtos.EvaluationRunSummary;
import com.agentshield.governance.EvidenceExportDtos.EvidenceBundle;
import com.agentshield.governance.EvidenceExportDtos.PolicyDecisionEvent;
import com.agentshield.governance.EvidenceExportDtos.ToolCallEvent;
import com.agentshield.policy.PolicyDecision;
import com.agentshield.policy.PolicyDecisionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import org.springframework.stereotype.Service;

/**
 * Builds a versioned evidence bundle for a date range (agentshield_policy_evidence_execution_plan
 * _2026-07-30.md work package 5) — JSON is canonical; {@link #toSarif} is a constrained
 * compatibility projection of policy/evaluation findings only, not a claim that every operational
 * event is a static-analysis result. Every field here is derived from existing operational
 * tables — no new mutable source of truth — and deliberately excludes raw credentials, request
 * bodies, raw tool responses, encrypted values, and arbitrary audit metadata.
 */
@Service
public class EvidenceExportService {

    public static final String EXPORTER_VERSION = "1";
    public static final String REDACTION_POLICY_VERSION = "1";

    private final GatewayRequestRepository gatewayRequestRepository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final ApprovalRequestRepository approvalRequestRepository;
    private final EvaluationRunRepository evaluationRunRepository;
    private final ObjectMapper objectMapper;

    public EvidenceExportService(GatewayRequestRepository gatewayRequestRepository,
            PolicyDecisionRepository policyDecisionRepository, ApprovalRequestRepository approvalRequestRepository,
            EvaluationRunRepository evaluationRunRepository, ObjectMapper objectMapper) {
        this.gatewayRequestRepository = gatewayRequestRepository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.approvalRequestRepository = approvalRequestRepository;
        this.evaluationRunRepository = evaluationRunRepository;
        this.objectMapper = objectMapper;
    }

    public EvidenceBundle generate(Instant from, Instant to) {
        if (from == null || to == null || !from.isBefore(to)) {
            throw new ValidationException("from must be a timestamp strictly before to");
        }

        var toolCallEvents = gatewayRequestRepository.findByCreatedAtBetweenOrderByCreatedAtAsc(from, to).stream()
                .map(this::toToolCallEvent)
                .toList();
        var policyDecisionEvents = policyDecisionRepository.findByCreatedAtBetweenOrderByCreatedAtDesc(from, to)
                .stream().map(this::toPolicyDecisionEvent).toList();
        var approvalEvents = approvalRequestRepository.findByCreatedAtBetweenOrderByCreatedAtDesc(from, to).stream()
                .map(this::toApprovalEvent).toList();
        var evaluationRunSummaries = evaluationRunRepository.findByStartedAtBetweenOrderByStartedAtDesc(from, to)
                .stream().map(this::toEvaluationRunSummary).toList();

        return new EvidenceBundle("evidence-bundle-v1", EXPORTER_VERSION, Instant.now(), from, to,
                REDACTION_POLICY_VERSION, toolCallEvents, policyDecisionEvents, approvalEvents,
                evaluationRunSummaries);
    }

    /**
     * SARIF 2.1.0 projection: one result per non-ALLOW policy decision and per non-PASS
     * evaluation result in the bundle. Deliberately does not attempt to represent ALLOW/PASS
     * outcomes or raw tool-call events as SARIF — those have no static-analysis-finding analog.
     */
    public String toSarif(EvidenceBundle bundle) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("$schema", "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        root.put("version", "2.1.0");
        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();
        ObjectNode tool = run.putObject("tool");
        ObjectNode driver = tool.putObject("driver");
        driver.put("name", "AgentShield");
        driver.put("version", EXPORTER_VERSION);
        ArrayNode rules = driver.putArray("rules");
        ArrayNode results = run.putArray("results");

        java.util.Set<String> seenRuleIds = new java.util.LinkedHashSet<>();
        for (PolicyDecisionEvent event : bundle.policyDecisionEvents()) {
            if (event.decision() == com.agentshield.common.PolicyDecisionType.ALLOW || event.ruleId() == null) {
                continue;
            }
            addRuleIfNew(rules, seenRuleIds, event.ruleId());
            ObjectNode result = results.addObject();
            result.put("ruleId", event.ruleId());
            result.put("level", event.decision() == com.agentshield.common.PolicyDecisionType.DENY ? "error" : "warning");
            result.putObject("message").put("text", event.redactedReason() == null ? "" : event.redactedReason());
            ArrayNode locations = result.putArray("locations");
            locations.addObject().putArray("logicalLocations").addObject()
                    .put("fullyQualifiedName", "gateway-request/" + event.gatewayRequestId());
        }
        for (EvaluationRunSummary run1 : bundle.evaluationRunSummaries()) {
            if (run1.failedCases() == 0 && run1.errorCases() == 0) {
                continue;
            }
            String ruleId = "evaluation-run-has-failures";
            addRuleIfNew(rules, seenRuleIds, ruleId);
            ObjectNode result = results.addObject();
            result.put("ruleId", ruleId);
            result.put("level", "warning");
            result.putObject("message").put("text",
                    run1.failedCases() + " failed, " + run1.errorCases() + " errored out of " + run1.totalCases());
            ArrayNode locations = result.putArray("locations");
            locations.addObject().putArray("logicalLocations").addObject()
                    .put("fullyQualifiedName", "evaluation-run/" + run1.id());
        }
        return root.toString();
    }

    private void addRuleIfNew(ArrayNode rules, java.util.Set<String> seen, String ruleId) {
        if (seen.add(ruleId)) {
            rules.addObject().put("id", ruleId);
        }
    }

    private ToolCallEvent toToolCallEvent(GatewayRequest request) {
        return new ToolCallEvent("tool-call-event-v1", request.getId(), request.getCorrelationId(),
                request.getAgent().getId(), request.getAgent().getName(),
                request.getTool() != null ? request.getTool().getId() : null,
                request.getTool() != null ? request.getTool().getName() : null, request.getActionCategory(),
                request.getTargetEnvironment(), request.getStatus().name(), request.getCreatedAt());
    }

    private PolicyDecisionEvent toPolicyDecisionEvent(PolicyDecision decision) {
        return new PolicyDecisionEvent("policy-decision-event-v1", decision.getId(),
                decision.getGatewayRequest().getId(), decision.getDecision(), decision.getRuleId(),
                decision.getPolicyVersion(), decision.getReason(), decision.getRiskScore(),
                decision.getRiskLevel() != null ? decision.getRiskLevel().name() : null, decision.getCreatedAt());
    }

    private ApprovalEvent toApprovalEvent(ApprovalRequest approval) {
        Instant decidedAt = approval.getApprovedAt() != null ? approval.getApprovedAt() : approval.getRejectedAt();
        String decidedBy = approval.getApprovedBy() != null ? approval.getApprovedBy() : approval.getRejectedBy();
        return new ApprovalEvent("approval-event-v1", approval.getId(), approval.getGatewayRequest().getId(),
                approval.getStatus(), approval.getApprovalProfileId(),
                approval.getAssignedRole() != null ? approval.getAssignedRole().name() : null,
                approval.getRequestedBy(), decidedBy, approval.getCreatedAt(), decidedAt);
    }

    private EvaluationRunSummary toEvaluationRunSummary(EvaluationRun run) {
        return new EvaluationRunSummary("evaluation-run-v1", run.getId(), run.getSuiteId(), run.getSuiteVersion(),
                run.getPolicyConfigFingerprint(), run.getTriggeredBy(), run.getStartedAt(), run.getCompletedAt(),
                run.getTotalCases(), run.getPassedCases(), run.getFailedCases(), run.getErrorCases());
    }
}
