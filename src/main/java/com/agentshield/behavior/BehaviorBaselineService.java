package com.agentshield.behavior;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.incident.IncidentService;
import com.agentshield.policy.PolicyDecisionRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Wires {@link BehaviorBaselineRules} to real gateway/policy history and, when a request trips
 * one or more checks, records a WARNING audit event and a WARNING-severity incident
 * (improvement_plan.md P2 "Agent Behavior Baselines And Anomaly Detection" — "unusual-but-allowed
 * behavior creates a warning incident or audit event", never a hard block: this runs after the
 * policy decision is already made and never changes it).
 */
@Service
public class BehaviorBaselineService {

    private final GatewayRequestRepository gatewayRequestRepository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final AuditService auditService;
    private final IncidentService incidentService;
    private final BaselineThresholds thresholds;

    public BehaviorBaselineService(GatewayRequestRepository gatewayRequestRepository,
            PolicyDecisionRepository policyDecisionRepository, AuditService auditService,
            IncidentService incidentService) {
        this.gatewayRequestRepository = gatewayRequestRepository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.auditService = auditService;
        this.incidentService = incidentService;
        this.thresholds = BaselineThresholds.defaults();
    }

    @Transactional
    public void evaluate(GatewayRequest gatewayRequest, boolean firstTimeCombination) {
        Long agentId = gatewayRequest.getAgent().getId();
        Instant now = Instant.now();

        long totalPrior = gatewayRequestRepository.countByAgentId(agentId);
        Instant firstRequestAt = gatewayRequestRepository.findTopByAgentIdOrderByCreatedAtAsc(agentId)
                .map(GatewayRequest::getCreatedAt)
                .orElse(now);
        long trailingHourCount = gatewayRequestRepository.countByAgentIdAndCreatedAtAfter(agentId,
                now.minus(Duration.ofHours(1)));
        long recentDenials = policyDecisionRepository.countByGatewayRequest_AgentIdAndDecisionAndCreatedAtAfter(
                agentId, PolicyDecisionType.DENY, now.minus(Duration.ofMinutes(thresholds.denialWindowMinutes())));
        long recentApprovals = policyDecisionRepository.countByGatewayRequest_AgentIdAndDecisionAndCreatedAtAfter(
                agentId, PolicyDecisionType.APPROVAL_REQUIRED,
                now.minus(Duration.ofMinutes(thresholds.approvalFrequencyWindowMinutes())));

        BaselineInputs inputs = new BaselineInputs(firstTimeCombination, totalPrior, firstRequestAt,
                trailingHourCount, recentDenials, recentApprovals);
        List<BaselineFinding> findings = BehaviorBaselineRules.evaluate(inputs, thresholds, now);
        if (findings.isEmpty()) {
            return;
        }

        String agentName = gatewayRequest.getAgent().getName();
        String summary = "Agent '" + agentName + "' tripped behavior baseline check(s): "
                + findings.stream().map(BaselineFinding::message).collect(Collectors.joining("; "));

        var auditEvent = auditService.record(gatewayRequest.getCorrelationId(), "behavior.anomaly_detected",
                ActorType.SYSTEM, "behavior-baseline", agentId,
                gatewayRequest.getTool() != null ? gatewayRequest.getTool().getId() : null, AuditSeverity.WARNING,
                summary, null);
        incidentService.createWarning("Unusual behavior: agent '" + agentName + "'", summary, auditEvent.getId(),
                gatewayRequest.getId());
    }
}
