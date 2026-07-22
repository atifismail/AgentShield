package com.agentshield.policy;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentRepository;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.PolicyMode;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.ValidationException;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.policy.PolicyDtos.DryRunRequest;
import com.agentshield.policy.PolicyDtos.ReplayResponse;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolRepository;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PolicyService {

    private final PolicyRepository policyRepository;
    private final AgentRepository agentRepository;
    private final ToolRepository toolRepository;
    private final GatewayRequestRepository gatewayRequestRepository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final PolicyEngine policyEngine;
    private final AuditService auditService;

    public PolicyService(PolicyRepository policyRepository, AgentRepository agentRepository,
            ToolRepository toolRepository, GatewayRequestRepository gatewayRequestRepository,
            PolicyDecisionRepository policyDecisionRepository, PolicyEngine policyEngine, AuditService auditService) {
        this.policyRepository = policyRepository;
        this.agentRepository = agentRepository;
        this.toolRepository = toolRepository;
        this.gatewayRequestRepository = gatewayRequestRepository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.policyEngine = policyEngine;
        this.auditService = auditService;
    }

    public List<Policy> listAll() {
        return policyRepository.findAllByOrderByNameAscVersionDesc();
    }

    public List<Policy> versionsOf(String name) {
        return policyRepository.findByNameOrderByVersionDesc(name);
    }

    @Transactional
    public Policy createVersion(String name, String ruleJson, PolicyMode mode, String createdBy) {
        int nextVersion = policyRepository.findByNameOrderByVersionDesc(name).stream()
                .findFirst().map(p -> p.getVersion() + 1).orElse(1);
        Policy policy = new Policy();
        policy.setName(name);
        policy.setVersion(nextVersion);
        policy.setEnabled(false);
        policy.setMode(mode == null ? PolicyMode.ENFORCE : mode);
        policy.setRuleJson(ruleJson);
        policy.setCreatedBy(createdBy);
        policy = policyRepository.save(policy);
        auditService.record(null, "policy.version_created", ActorType.USER, createdBy, null, null,
                AuditSeverity.INFO, "policy '" + name + "' version " + nextVersion + " created", null);
        return policy;
    }

    @Transactional
    public Policy setEnabled(Long id, boolean enabled) {
        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("policy " + id + " not found"));
        if (enabled) {
            versionsOf(policy.getName()).stream()
                    .filter(other -> !other.getId().equals(id) && other.isEnabled())
                    .forEach(other -> other.setEnabled(false));
        }
        policy.setEnabled(enabled);
        auditService.record(null, enabled ? "policy.enabled" : "policy.disabled", ActorType.USER, null, null, null,
                AuditSeverity.WARNING,
                "policy '" + policy.getName() + "' version " + policy.getVersion() + " "
                        + (enabled ? "enabled" : "disabled"),
                null);
        return policy;
    }

    /** Pure evaluation against the live rule set — no side effects, no persistence. */
    public PolicyOutcome dryRun(DryRunRequest request) {
        Agent agent = agentRepository.findById(request.agentId())
                .orElseThrow(() -> new ResourceNotFoundException("agent " + request.agentId() + " not found"));
        Tool tool = toolRepository.findById(request.toolId())
                .orElseThrow(() -> new ResourceNotFoundException("tool " + request.toolId() + " not found"));
        PolicyEvaluationContext ctx = new PolicyEvaluationContext(agent, tool, request.actionCategory(),
                request.targetEnvironment(), request.payloadSizeBytes(), 0);
        return policyEngine.evaluateRequest(ctx);
    }

    /**
     * Replays a historical gateway request's facts against the live policy engine (including any
     * policy overrides in force right now) without touching the downstream tool or persisting
     * anything — lets an operator see whether a policy change would have altered a past decision.
     */
    public ReplayResponse replay(Long gatewayRequestId) {
        GatewayRequest gatewayRequest = gatewayRequestRepository.findById(gatewayRequestId)
                .orElseThrow(() -> new ResourceNotFoundException("gateway request " + gatewayRequestId + " not found"));
        if (gatewayRequest.getTool() == null) {
            throw new ValidationException(
                    "gateway request " + gatewayRequestId + " has no resolved tool and cannot be replayed");
        }

        int payloadSizeBytes = gatewayRequest.getRequestBodyJson() == null
                ? 0
                : gatewayRequest.getRequestBodyJson().getBytes(StandardCharsets.UTF_8).length;
        PolicyEvaluationContext ctx = new PolicyEvaluationContext(gatewayRequest.getAgent(), gatewayRequest.getTool(),
                gatewayRequest.getActionCategory(), gatewayRequest.getTargetEnvironment(), payloadSizeBytes, 0);
        PolicyOutcome simulated = policyEngine.evaluateRequest(ctx);

        var original = policyDecisionRepository.findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc(gatewayRequestId);
        var originalDecision = original.map(PolicyDecision::getDecision).orElse(null);
        var originalReason = original.map(PolicyDecision::getReason).orElse(null);

        return new ReplayResponse(gatewayRequestId, originalDecision, originalReason, simulated.decision(),
                simulated.reason(), simulated.ruleId(), !Objects.equals(originalDecision, simulated.decision()));
    }
}
