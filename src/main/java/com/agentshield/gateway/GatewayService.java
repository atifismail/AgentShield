package com.agentshield.gateway;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.approval.ApprovalRequest;
import com.agentshield.approval.ApprovalRequestRepository;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.AuthenticationFailedException;
import com.agentshield.common.GatewayRequestStatus;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.RiskLevel;
import com.agentshield.common.TokenHasher;
import com.agentshield.gateway.GatewayDtos.InvokeRequest;
import com.agentshield.gateway.GatewayDtos.InvokeResponse;
import com.agentshield.incident.IncidentService;
import com.agentshield.metrics.GatewayMetrics;
import com.agentshield.policy.PolicyDecision;
import com.agentshield.policy.PolicyDecisionRepository;
import com.agentshield.policy.PolicyEngine;
import com.agentshield.policy.PolicyEvaluationContext;
import com.agentshield.policy.PolicyOutcome;
import com.agentshield.risk.PromptInjectionDetector;
import com.agentshield.risk.RiskAssessment;
import com.agentshield.risk.RiskInput;
import com.agentshield.risk.RiskScorer;
import com.agentshield.risk.SecretDetector;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Orchestrates a single gateway call: authenticate, normalize, evaluate policy + risk,
 * forward if allowed, scan the response, and audit every step. Fail-closed: any unexpected
 * exception during evaluation is treated as a DENY, never a silent ALLOW (AGENTS.md rule 6).
 */
@Service
public class GatewayService {

    private static final int MAX_SUMMARY_CHARS = 4000;

    private final AgentCredentialRepository agentCredentialRepository;
    private final ToolRepository toolRepository;
    private final GatewayRequestRepository gatewayRequestRepository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final ApprovalRequestRepository approvalRequestRepository;
    private final PolicyEngine policyEngine;
    private final RiskScorer riskScorer;
    private final PromptInjectionDetector injectionDetector;
    private final SecretDetector secretDetector;
    private final ToolForwarder toolForwarder;
    private final AuditService auditService;
    private final IncidentService incidentService;
    private final ObjectMapper objectMapper;
    private final GatewayToolResponseRepository toolResponseRepository;
    private final RawResponseEncryptor rawResponseEncryptor;
    private final GatewayMetrics metrics;
    private final int maxPayloadBytes;
    private final int defaultApprovalExpirationMinutes;

    public GatewayService(AgentCredentialRepository agentCredentialRepository, ToolRepository toolRepository,
            GatewayRequestRepository gatewayRequestRepository, PolicyDecisionRepository policyDecisionRepository,
            ApprovalRequestRepository approvalRequestRepository, PolicyEngine policyEngine, RiskScorer riskScorer,
            PromptInjectionDetector injectionDetector, SecretDetector secretDetector, ToolForwarder toolForwarder,
            AuditService auditService, IncidentService incidentService, ObjectMapper objectMapper,
            GatewayToolResponseRepository toolResponseRepository, RawResponseEncryptor rawResponseEncryptor,
            GatewayMetrics metrics,
            @Value("${agentshield.gateway.max-payload-bytes:262144}") int maxPayloadBytes,
            @Value("${agentshield.approval.default-expiration-minutes:60}") int defaultApprovalExpirationMinutes) {
        this.agentCredentialRepository = agentCredentialRepository;
        this.toolRepository = toolRepository;
        this.gatewayRequestRepository = gatewayRequestRepository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.approvalRequestRepository = approvalRequestRepository;
        this.policyEngine = policyEngine;
        this.riskScorer = riskScorer;
        this.injectionDetector = injectionDetector;
        this.secretDetector = secretDetector;
        this.toolForwarder = toolForwarder;
        this.auditService = auditService;
        this.incidentService = incidentService;
        this.objectMapper = objectMapper;
        this.toolResponseRepository = toolResponseRepository;
        this.rawResponseEncryptor = rawResponseEncryptor;
        this.metrics = metrics;
        this.maxPayloadBytes = maxPayloadBytes;
        this.defaultApprovalExpirationMinutes = defaultApprovalExpirationMinutes;
    }

    /**
     * Looks up the credential by hash and requires it to be ACTIVE and unexpired — a revoked or
     * expired token authenticates nothing, regardless of how recently it worked
     * (improvement_plan.md #3). Updates last-used-at on success.
     */
    @Transactional
    public Agent authenticate(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new AuthenticationFailedException("missing agent bearer token");
        }
        String token = bearerToken.startsWith("Bearer ") ? bearerToken.substring(7) : bearerToken;
        String hash = TokenHasher.sha256Hex(token);
        AgentCredential credential = agentCredentialRepository.findByTokenHash(hash)
                .orElseThrow(() -> new AuthenticationFailedException("invalid agent token"));
        if (!credential.isUsable(Instant.now())) {
            throw new AuthenticationFailedException("agent token is " + credential.getStatus().name().toLowerCase());
        }
        credential.setLastUsedAt(Instant.now());
        return credential.getAgent();
    }

    @Transactional
    public InvokeResponse invoke(String bearerToken, InvokeRequest request) {
        metrics.requestReceived();
        var gatewayTimer = metrics.startTimer();
        try {
            return doInvoke(bearerToken, request);
        } finally {
            metrics.stopGatewayTimer(gatewayTimer);
        }
    }

    private InvokeResponse doInvoke(String bearerToken, InvokeRequest request) {
        Agent agent = authenticate(bearerToken);
        String correlationId = UUID.randomUUID().toString();

        Optional<Tool> toolOpt = toolRepository.findByName(request.toolId());
        if (toolOpt.isEmpty()) {
            GatewayRequest gatewayRequest = persistRequest(correlationId, agent, null, request, "");
            gatewayRequest.setStatus(GatewayRequestStatus.DENIED);
            String reason = "tool '" + request.toolId() + "' is not registered";
            recordDecision(gatewayRequest, PolicyDecisionType.DENY, reason, 0, RiskLevel.LOW);
            auditService.record(correlationId, "gateway.denied", ActorType.AGENT, agent.getName(), agent.getId(),
                    null, AuditSeverity.WARNING, reason, null);
            return InvokeResponse.deny(RiskLevel.LOW, reason);
        }
        Tool tool = toolOpt.get();

        String inputJson = writeJsonSafely(request.input());
        int payloadBytes = inputJson.getBytes(StandardCharsets.UTF_8).length;
        boolean firstTimePair = !gatewayRequestRepository.existsByAgentIdAndToolId(agent.getId(), tool.getId());

        GatewayRequest gatewayRequest = persistRequest(correlationId, agent, tool, request, inputJson);

        auditService.record(correlationId, "gateway.request_received", ActorType.AGENT, agent.getName(),
                agent.getId(), tool.getId(), AuditSeverity.INFO,
                "agent '" + agent.getName() + "' requested action '" + request.action() + "' on tool '"
                        + tool.getName() + "'", null);

        PolicyOutcome policyOutcome;
        RiskAssessment riskAssessment;
        try {
            PolicyEvaluationContext ctx = new PolicyEvaluationContext(agent, tool, request.actionCategory(),
                    request.targetEnvironment(), payloadBytes, maxPayloadBytes);
            var policyTimer = metrics.startTimer();
            policyOutcome = policyEngine.evaluateRequest(ctx);
            metrics.stopPolicyEvaluationTimer(policyTimer);

            RiskInput riskInput = RiskInput.builder(request.actionCategory())
                    .prodEnvironment(ctx.isProd())
                    .toolNotApproved(tool.getApprovalStatus() != ToolApprovalStatus.APPROVED)
                    .schemaDrift(tool.getApprovalStatus() == ToolApprovalStatus.DRIFTED || tool.hasDrift())
                    .firstTimeAgentToolPair(firstTimePair)
                    .build();
            riskAssessment = riskScorer.score(riskInput);
        } catch (Exception e) {
            policyOutcome = new PolicyOutcome(PolicyDecisionType.DENY,
                    "policy evaluation failed, failing closed: " + e.getMessage(), "fail-closed-error");
            riskAssessment = new RiskAssessment(100, RiskLevel.CRITICAL, List.of("policy evaluation threw an exception"));
        }

        recordDecision(gatewayRequest, policyOutcome.decision(), policyOutcome.reason(), riskAssessment.score(),
                riskAssessment.level());
        auditService.record(correlationId, "gateway.policy_decision", ActorType.SYSTEM, "policy-engine",
                agent.getId(), tool.getId(), severityFor(policyOutcome.decision()),
                "policy decision " + policyOutcome.decision() + " [" + policyOutcome.ruleId() + "]: "
                        + policyOutcome.reason(),
                Map.of("riskScore", riskAssessment.score(), "riskLevel", riskAssessment.level().name()));

        return switch (policyOutcome.decision()) {
            case DENY -> {
                gatewayRequest.setStatus(GatewayRequestStatus.DENIED);
                auditService.record(correlationId, "gateway.denied", ActorType.SYSTEM, "policy-engine",
                        agent.getId(), tool.getId(), AuditSeverity.WARNING, policyOutcome.reason(), null);
                yield InvokeResponse.deny(riskAssessment.level(), policyOutcome.reason());
            }
            case APPROVAL_REQUIRED -> {
                gatewayRequest.setStatus(GatewayRequestStatus.PENDING_APPROVAL);
                ApprovalRequest approval = new ApprovalRequest();
                approval.setGatewayRequest(gatewayRequest);
                approval.setRequestedBy(contextValue(request, "userId"));
                approval.setReason(policyOutcome.reason());
                approval.setExpiresAt(Instant.now().plus(Duration.ofMinutes(defaultApprovalExpirationMinutes)));
                approval = approvalRequestRepository.save(approval);
                auditService.record(correlationId, "gateway.approval_required", ActorType.SYSTEM, "policy-engine",
                        agent.getId(), tool.getId(), AuditSeverity.WARNING, policyOutcome.reason(), null);
                yield InvokeResponse.approvalRequired(riskAssessment.level(), policyOutcome.reason(), approval.getId());
            }
            default -> executeAndScan(gatewayRequest, tool, request.actionCategory(), request.input(), riskAssessment);
        };
    }

    /**
     * Forwards an ALLOWed (or now-approved) call to its tool and scans the response.
     * Shared by the initial invoke path and the approval-workflow execution path.
     */
    @Transactional
    public InvokeResponse executeAndScan(GatewayRequest gatewayRequest, Tool tool, ActionCategory actionCategory,
            JsonNode input, RiskAssessment preCallRisk) {
        String correlationId = gatewayRequest.getCorrelationId();
        var forwardTimer = metrics.startTimer();
        ToolForwarder.ToolCallResult callResult = toolForwarder.call(tool, input);
        metrics.stopToolForwardTimer(forwardTimer);

        if (!callResult.success()) {
            gatewayRequest.setStatus(GatewayRequestStatus.FAILED);
            String reason = callResult.blockedByPolicy()
                    ? callResult.errorMessage()
                    : "tool call failed: " + callResult.errorMessage();
            String eventType = callResult.blockedByPolicy() ? "gateway.outbound_blocked" : "gateway.tool_call_failed";
            AuditSeverity severity = callResult.blockedByPolicy() ? AuditSeverity.CRITICAL : AuditSeverity.WARNING;
            auditService.record(correlationId, eventType, ActorType.SYSTEM, "gateway",
                    gatewayRequest.getAgent().getId(), tool.getId(), severity, reason, null);
            return InvokeResponse.deny(preCallRisk.level(), reason);
        }

        boolean destinationExternal = actionCategory == ActionCategory.EXTERNAL_TRANSFER;
        var secretResult = secretDetector.scan(callResult.rawBody());
        var injectionResult = injectionDetector.scan(callResult.rawBody());
        var responsePolicyTimer = metrics.startTimer();
        PolicyOutcome responseOutcome = policyEngine.evaluateResponse(destinationExternal, secretResult, injectionResult);
        metrics.stopPolicyEvaluationTimer(responsePolicyTimer);
        boolean blocked = !responseOutcome.isAllow();

        recordToolResponse(gatewayRequest, callResult, blocked, blocked ? responseOutcome.reason() : null,
                secretResult, injectionResult);

        if (blocked) {
            metrics.responseBlocked();
            RiskInput rescored = RiskInput.builder(actionCategory)
                    .secretConfidence(secretResult.highestConfidence())
                    .injectionConfidence(injectionResult.highestConfidence())
                    .build();
            RiskAssessment finalRisk = riskScorer.score(rescored);

            gatewayRequest.setStatus(GatewayRequestStatus.FAILED);
            recordDecision(gatewayRequest, PolicyDecisionType.DENY, responseOutcome.reason(), finalRisk.score(),
                    RiskLevel.CRITICAL);
            var auditEvent = auditService.record(correlationId, "gateway.response_blocked", ActorType.SYSTEM,
                    "response-scanner", gatewayRequest.getAgent().getId(), tool.getId(), AuditSeverity.CRITICAL,
                    responseOutcome.reason(), null);
            incidentService.createFromFinding("Blocked tool response: " + responseOutcome.ruleId(),
                    responseOutcome.reason(), auditEvent.getId(), gatewayRequest.getId());
            return InvokeResponse.deny(RiskLevel.CRITICAL, responseOutcome.reason());
        }

        gatewayRequest.setStatus(GatewayRequestStatus.COMPLETED);
        auditService.record(correlationId, "gateway.allowed", ActorType.SYSTEM, "gateway",
                gatewayRequest.getAgent().getId(), tool.getId(), AuditSeverity.INFO,
                "call allowed and forwarded to tool '" + tool.getName() + "'", null);
        return InvokeResponse.allow(preCallRisk.level(), callResult.parsedBody());
    }

    private GatewayRequest persistRequest(String correlationId, Agent agent, Tool tool, InvokeRequest request,
            String inputJson) {
        GatewayRequest gatewayRequest = new GatewayRequest();
        gatewayRequest.setCorrelationId(correlationId);
        gatewayRequest.setUserId(contextValue(request, "userId"));
        gatewayRequest.setAgent(agent);
        gatewayRequest.setTool(tool);
        gatewayRequest.setActionName(request.action());
        gatewayRequest.setActionCategory(request.actionCategory());
        gatewayRequest.setTargetEnvironment(request.targetEnvironment());
        gatewayRequest.setRequestBodyHash(TokenHasher.sha256Hex(inputJson));
        gatewayRequest.setRequestSummary(truncate(inputJson));
        gatewayRequest.setRequestBodyJson(inputJson);
        gatewayRequest.setStatus(GatewayRequestStatus.ALLOWED);
        return gatewayRequestRepository.save(gatewayRequest);
    }

    /**
     * Forensic record of what the tool actually returned, without storing the raw body by
     * default (improvement_plan.md #7). response_summary is a preview of the raw body when the
     * response was clean/ALLOWed (the agent already received exactly this content, so storing a
     * preview of it isn't a new exposure) — but when the response was blocked, it's replaced
     * with just the matched detector indicator names, never the raw matched text.
     */
    private void recordToolResponse(GatewayRequest gatewayRequest, ToolForwarder.ToolCallResult callResult,
            boolean blocked, String blockReason, com.agentshield.risk.DetectionResult secretResult,
            com.agentshield.risk.DetectionResult injectionResult) {
        GatewayToolResponse response = new GatewayToolResponse();
        response.setGatewayRequest(gatewayRequest);
        response.setStatusCode(callResult.statusCode());
        response.setBlocked(blocked);
        response.setBlockReason(blockReason);

        String rawBody = callResult.rawBody();
        if (rawBody != null) {
            response.setResponseBodyHash(TokenHasher.sha256Hex(rawBody));
        }
        response.setResponseSummary(blocked
                ? "[response blocked — see block_reason and detector_matches_json]"
                : truncate(rawBody));

        ArrayNode matches = objectMapper.createArrayNode();
        appendMatches(matches, secretResult);
        appendMatches(matches, injectionResult);
        if (!matches.isEmpty()) {
            response.setDetectorMatchesJson(matches.toString());
        }

        if (rawResponseEncryptor.isEnabled() && rawBody != null) {
            response.setRawResponseEncrypted(rawResponseEncryptor.encrypt(rawBody));
        }

        toolResponseRepository.save(response);
    }

    private void appendMatches(ArrayNode target, com.agentshield.risk.DetectionResult result) {
        for (com.agentshield.risk.DetectionMatch match : result.matches()) {
            ObjectNode entry = objectMapper.createObjectNode();
            entry.put("indicator", match.indicator());
            entry.put("category", match.category().name());
            entry.put("confidence", match.confidence().name());
            entry.put("line", match.line());
            target.add(entry);
        }
    }

    private void recordDecision(GatewayRequest gatewayRequest, PolicyDecisionType decision, String reason,
            int riskScore, RiskLevel riskLevel) {
        PolicyDecision decisionRecord = new PolicyDecision();
        decisionRecord.setGatewayRequest(gatewayRequest);
        decisionRecord.setDecision(decision);
        decisionRecord.setPolicyVersion("default-policy-v1");
        decisionRecord.setReason(reason);
        decisionRecord.setRiskScore(riskScore);
        decisionRecord.setRiskLevel(riskLevel);
        policyDecisionRepository.save(decisionRecord);
        metrics.decisionRecorded(decision);
    }

    private AuditSeverity severityFor(PolicyDecisionType decision) {
        return switch (decision) {
            case ALLOW -> AuditSeverity.INFO;
            case APPROVAL_REQUIRED -> AuditSeverity.WARNING;
            case DENY -> AuditSeverity.WARNING;
        };
    }

    private String contextValue(InvokeRequest request, String key) {
        if (request.context() == null) {
            return null;
        }
        Object value = request.context().get(key);
        return value == null ? null : value.toString();
    }

    private String writeJsonSafely(JsonNode node) {
        if (node == null) {
            return "{}";
        }
        return node.toString();
    }

    private String truncate(String text) {
        if (text == null) {
            return null;
        }
        return text.length() <= MAX_SUMMARY_CHARS ? text : text.substring(0, MAX_SUMMARY_CHARS);
    }
}
