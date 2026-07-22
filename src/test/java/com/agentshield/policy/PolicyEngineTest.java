package com.agentshield.policy;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.dlp.DlpAction;
import com.agentshield.mcp.McpConsentService;
import com.agentshield.risk.Confidence;
import com.agentshield.risk.DetectionMatch;
import com.agentshield.risk.DetectionResult;
import com.agentshield.risk.DetectorCategory;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolType;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class PolicyEngineTest {

    // No overrides configured for these tests — they exercise the fixed rules in isolation.
    // PolicyOverrideTest covers the override layer itself.
    private final PolicyOverrideRepository overrideRepository = Mockito.mock(PolicyOverrideRepository.class);
    private final McpConsentService mcpConsentService = Mockito.mock(McpConsentService.class);
    private final PolicyEngine engine = new PolicyEngine(overrideRepository, mcpConsentService);

    {
        Mockito.when(overrideRepository.findActiveOrderByPriority()).thenReturn(List.of());
    }

    private Agent agent(AgentStatus status, String... allowedGroups) {
        Agent agent = new Agent();
        agent.setName("test-agent");
        agent.setStatus(status);
        agent.setAllowedToolGroups(allowedGroups.length == 0 ? null : String.join(",", allowedGroups));
        return agent;
    }

    private Tool tool(ToolApprovalStatus status, String approvedHash, String currentHash, String group) {
        Tool tool = new Tool();
        tool.setName("test-tool");
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup(group);
        tool.setApprovalStatus(status);
        tool.setApprovedHash(approvedHash);
        tool.setCurrentHash(currentHash);
        return tool;
    }

    private PolicyEvaluationContext ctx(Agent agent, Tool tool, ActionCategory category, String env, int payload) {
        return new PolicyEvaluationContext(agent, tool, category, env, payload, 1000);
    }

    private DetectionResult detected(String indicator, DetectorCategory category) {
        return new DetectionResult(true, List.of(new DetectionMatch(indicator, category, Confidence.HIGH, 0, indicator.length(), 1)));
    }

    @Test
    void rule1_deniesDisabledAgent() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.DISABLED, "db"),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "db"),
                ActionCategory.READ, "DEV", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-disabled-agent");
    }

    @Test
    void rule2_deniesUnapprovedTool() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "db"),
                tool(ToolApprovalStatus.PENDING, null, "h", "db"),
                ActionCategory.READ, "DEV", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-unapproved-tool");
    }

    @Test
    void rule3_deniesSchemaDrift() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "db"),
                tool(ToolApprovalStatus.DRIFTED, "old-hash", "new-hash", "db"),
                ActionCategory.READ, "DEV", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-schema-drift");
    }

    @Test
    void rule4_deniesProdDestructiveOutright() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "db"),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "db"),
                ActionCategory.DESTRUCTIVE, "PROD", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-prod-destructive-without-approval");
    }

    @Test
    void rule5_requiresApprovalForProdWrite() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "db"),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "db"),
                ActionCategory.WRITE, "PROD", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.APPROVAL_REQUIRED);
        assertThat(outcome.ruleId()).isEqualTo("require-approval-prod-write");
    }

    @Test
    void rule6_requiresApprovalForExternalTransfer() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "saas"),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "saas"),
                ActionCategory.EXTERNAL_TRANSFER, "DEV", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.APPROVAL_REQUIRED);
        assertThat(outcome.ruleId()).isEqualTo("require-approval-external-transfer");
    }

    @Test
    void rule7_deniesSecretInResponseWhenExternal() {
        var outcome = engine.evaluateResponse(true,
                detected("api-key-assignment", DetectorCategory.CREDENTIAL), DetectionResult.CLEAN);
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-secret-external-transfer");
    }

    @Test
    void rule7_allowsSecretInResponseWhenNotExternal() {
        var outcome = engine.evaluateResponse(false,
                detected("api-key-assignment", DetectorCategory.CREDENTIAL), DetectionResult.CLEAN);
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void rule8_deniesPromptInjectionInResponse() {
        var outcome = engine.evaluateResponse(false, DetectionResult.CLEAN,
                detected("ignore previous instructions", DetectorCategory.PROMPT_OVERRIDE));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-prompt-injection-response");
    }

    @Test
    void rule9_deniesToolOutsideAllowedGroup() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "filesystem"),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "database"),
                ActionCategory.READ, "DEV", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-tool-outside-allowed-group");
    }

    @Test
    void rule9_deniesWhenAgentHasNoAllowedGroupsConfigured() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "database"),
                ActionCategory.READ, "DEV", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-tool-outside-allowed-group");
    }

    @Test
    void rule10_deniesOversizedPayload() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "db"),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "db"),
                ActionCategory.READ, "DEV", 5000));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-oversized-payload");
    }

    @Test
    void allowsWhenNoRuleMatches() {
        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "db"),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "db"),
                ActionCategory.READ, "DEV", 10));
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void rule11_deniesMcpBackedToolWithoutActiveConsent() {
        Tool mcpTool = tool(ToolApprovalStatus.APPROVED, "h", "h", "mcp");
        mcpTool.setMcpServerId(1L);
        mcpTool.setMcpToolName("echo");
        Mockito.when(mcpConsentService.hasActiveConsent(Mockito.any(), Mockito.eq(1L), Mockito.eq("echo"),
                Mockito.eq(ActionCategory.READ))).thenReturn(false);

        var outcome = engine.evaluateRequest(ctx(agent(AgentStatus.ENABLED, "mcp"), mcpTool, ActionCategory.READ, "DEV", 10));

        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-missing-mcp-consent");
    }

    @Test
    void rule11_allowsMcpBackedToolWithActiveConsent() {
        Tool mcpTool = tool(ToolApprovalStatus.APPROVED, "h", "h", "mcp");
        mcpTool.setMcpServerId(1L);
        mcpTool.setMcpToolName("echo");
        Mockito.when(mcpConsentService.hasActiveConsent(Mockito.any(), Mockito.eq(1L), Mockito.eq("echo"),
                Mockito.eq(ActionCategory.READ))).thenReturn(true);

        var outcome = engine.evaluateRequest(ctx(agent(AgentStatus.ENABLED, "mcp"), mcpTool, ActionCategory.READ, "DEV", 10));

        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void rule11_doesNotApplyToNonMcpTools() {
        // Plain HTTP tool — mcpServerId stays null, isMcpBacked() is false, rule 11 is a no-op
        // regardless of what hasActiveConsent would return.
        Mockito.when(mcpConsentService.hasActiveConsent(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(false);

        var outcome = engine.evaluateRequest(ctx(
                agent(AgentStatus.ENABLED, "db"),
                tool(ToolApprovalStatus.APPROVED, "h", "h", "db"),
                ActionCategory.READ, "DEV", 10));

        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void evaluateDlp_allowsWhenActionIsAllow() {
        var outcome = engine.evaluateDlp(DlpAction.ALLOW, List.of());
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void evaluateDlp_allowsWhenActionIsRedactOrTokenize_contentAlreadySanitized() {
        var match = detected("aws-access-key", com.agentshield.risk.DetectorCategory.CREDENTIAL);
        assertThat(engine.evaluateDlp(DlpAction.REDACT, match.matches()).decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(engine.evaluateDlp(DlpAction.TOKENIZE, match.matches()).decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void evaluateDlp_deniesWhenActionIsBlock() {
        var match = detected("aws-access-key", com.agentshield.risk.DetectorCategory.CREDENTIAL);
        var outcome = engine.evaluateDlp(DlpAction.BLOCK, match.matches());
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(outcome.ruleId()).isEqualTo("deny-dlp-block");
        assertThat(outcome.reason()).contains("aws-access-key");
    }

    @Test
    void evaluateDlp_requiresApprovalWhenActionIsApprovalRequired() {
        var match = detected("email-address", com.agentshield.risk.DetectorCategory.EMAIL);
        var outcome = engine.evaluateDlp(DlpAction.APPROVAL_REQUIRED, match.matches());
        assertThat(outcome.decision()).isEqualTo(PolicyDecisionType.APPROVAL_REQUIRED);
        assertThat(outcome.ruleId()).isEqualTo("require-approval-dlp-finding");
    }
}
