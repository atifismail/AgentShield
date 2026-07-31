package com.agentshield.evaluation;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.TokenHasher;
import com.agentshield.dlp.ContentStage;
import com.agentshield.dlp.DlpScanResult;
import com.agentshield.dlp.DlpScanService;
import com.agentshield.grant.GrantTransitionMode;
import com.agentshield.policy.PolicyEngine;
import com.agentshield.policy.PolicyEvaluationContext;
import com.agentshield.policy.PolicyOutcome;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * Evaluates one {@link EvaluationCase} against the real pre-call policy components — never a
 * {@code GatewayRequest}, {@code ToolForwarder}, MCP transport manager, or token acquisition
 * (agentshield_policy_evidence_execution_plan_2026-07-30.md work package 4). This class's only
 * collaborators are {@link PolicyEngine} (itself DB-reads-only: overrides, grants, MCP consent —
 * see its own javadoc) and {@link DlpScanService} (a pure pattern-matching scanner). Neither ever
 * touches a tool endpoint, subprocess, or external HTTP/OAuth call.
 */
@Component
public class EvaluationEngine {

    static final String EVALUATOR_VERSION = "1";

    private final PolicyEngine policyEngine;
    private final DlpScanService dlpScanService;
    private final ObjectMapper objectMapper;

    public EvaluationEngine(PolicyEngine policyEngine, DlpScanService dlpScanService, ObjectMapper objectMapper) {
        this.policyEngine = policyEngine;
        this.dlpScanService = dlpScanService;
        this.objectMapper = objectMapper;
    }

    public EvaluationResult evaluate(EvaluationRun run, EvaluationCase evaluationCase) {
        long start = System.nanoTime();
        EvaluationResult result = new EvaluationResult();
        result.setRunId(run.getId());
        result.setCaseId(evaluationCase.getId());
        result.setEvaluatorVersion(EVALUATOR_VERSION);

        try {
            EvaluationCaseFixture fixture = objectMapper.readValue(evaluationCase.getInputFixtureJson(),
                    EvaluationCaseFixture.class);
            PolicyOutcome outcome = evaluateFixture(fixture);
            result.setActualDecision(outcome.decision());
            result.setActualRuleId(outcome.ruleId());

            boolean decisionMatches = outcome.decision() == evaluationCase.getExpectedDecision();
            boolean ruleMatches = evaluationCase.getExpectedRuleId() == null
                    || evaluationCase.getExpectedRuleId().equals(outcome.ruleId());
            result.setResultStatus(decisionMatches && ruleMatches ? EvaluationResultStatus.PASS
                    : EvaluationResultStatus.FAIL);
            result.setRedactedReason(decisionMatches && ruleMatches ? null
                    : "expected " + evaluationCase.getExpectedDecision() + "/" + evaluationCase.getExpectedRuleId()
                            + " but got " + outcome.decision() + "/" + outcome.ruleId());
        } catch (Exception e) {
            // Fail closed: an unparseable or otherwise broken fixture is an ERROR, never a silent
            // PASS/ALLOW, and the recorded reason never echoes the raw fixture payload.
            result.setResultStatus(EvaluationResultStatus.ERROR);
            result.setRedactedReason("case '" + evaluationCase.getCaseKey() + "' failed to evaluate: "
                    + e.getClass().getSimpleName());
        }

        result.setDurationMillis((System.nanoTime() - start) / 1_000_000);
        return result;
    }

    private PolicyOutcome evaluateFixture(EvaluationCaseFixture fixture) {
        if (Boolean.TRUE.equals(fixture.unknownTool())) {
            return new PolicyOutcome(PolicyDecisionType.DENY, "tool is not registered", "deny-tool-not-registered");
        }
        if (fixture.actionCategory() == null) {
            throw new IllegalArgumentException("fixture is missing required field actionCategory");
        }

        Agent agent = buildAgent(fixture);
        Tool tool = buildTool(fixture);
        int payloadBytes = fixture.payloadSizeBytes() == null ? 10 : fixture.payloadSizeBytes();
        int maxPayloadBytes = fixture.maxPayloadSizeBytes() == null ? 262_144 : fixture.maxPayloadSizeBytes();

        PolicyEvaluationContext ctx = new PolicyEvaluationContext(agent, tool, fixture.actionCategory(),
                fixture.targetEnvironment(), payloadBytes, maxPayloadBytes);

        GrantTransitionMode mode = fixture.grantTransitionMode();
        PolicyOutcome outcome = mode == null ? policyEngine.evaluateRequest(ctx)
                : policyEngine.evaluateRequest(ctx, mode);

        if (!outcome.isAllow()) {
            return outcome;
        }
        if (fixture.dlpInputText() != null && !fixture.dlpInputText().isBlank()) {
            DlpScanResult dlpResult = dlpScanService.scan(fixture.dlpInputText(), ContentStage.TOOL_ARGUMENT,
                    "evaluation-" + Instant.now().toEpochMilli());
            PolicyOutcome dlpOutcome = policyEngine.evaluateDlp(dlpResult.action(), dlpResult.matches());
            if (!dlpOutcome.isAllow()) {
                return dlpOutcome;
            }
        }
        return outcome;
    }

    private Agent buildAgent(EvaluationCaseFixture fixture) {
        Agent agent = new Agent();
        agent.setId(fixture.agentId() != null ? fixture.agentId() : sentinelId(fixture, "agent"));
        agent.setName("evaluation-fixture-agent");
        agent.setStatus(Boolean.FALSE.equals(fixture.agentEnabled()) ? AgentStatus.DISABLED : AgentStatus.ENABLED);
        agent.setAllowedToolGroups(fixture.agentAllowedToolGroups());
        return agent;
    }

    private Tool buildTool(EvaluationCaseFixture fixture) {
        Tool tool = new Tool();
        tool.setId(fixture.toolId() != null ? fixture.toolId() : sentinelId(fixture, "tool"));
        tool.setName(fixture.toolName() == null ? "evaluation-fixture-tool" : fixture.toolName());
        tool.setToolGroup(fixture.toolGroup() == null ? "default" : fixture.toolGroup());
        tool.setApprovalStatus(fixture.toolApprovalStatus() == null ? ToolApprovalStatus.APPROVED
                : fixture.toolApprovalStatus());
        tool.setRiskTier(fixture.toolRiskTier());
        tool.setMcpServerId(fixture.toolMcpServerId());
        tool.setMcpToolName(fixture.toolMcpToolName());

        String baseline = "eval-fixture-hash";
        tool.setApprovedHash(baseline);
        tool.setCurrentHash(Boolean.TRUE.equals(fixture.toolHasDrift()) ? baseline + "-drifted" : baseline);
        return tool;
    }

    /**
     * Deterministic, clearly out-of-range negative ID so an unset agent/tool ID never
     * accidentally collides with a real persisted row when the grant/MCP-consent repositories
     * are queried by ID (a nonexistent pair correctly yields "no grant"/"no consent").
     */
    private long sentinelId(EvaluationCaseFixture fixture, String salt) {
        String basis = salt + "|" + fixture.actionCategory() + "|" + fixture.toolName() + "|" + fixture.agentAllowedToolGroups();
        long hash = TokenHasher.sha256Hex(basis).substring(0, 8).hashCode();
        return -1_000_000_000L - Math.abs(hash);
    }
}
