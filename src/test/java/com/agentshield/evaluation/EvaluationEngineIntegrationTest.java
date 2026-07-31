package com.agentshield.evaluation;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.PolicyDecisionType;
import com.agentshield.evaluation.EvaluationDtos.TriggerRunRequest;
import com.agentshield.gateway.ToolForwarder;
import com.agentshield.mcp.McpJsonRpcClient;
import com.agentshield.mcp.McpOAuthTokenService;
import com.agentshield.mcp.McpToolInvoker;
import com.agentshield.mcp.StdioMcpProcessManager;
import com.agentshield.support.AbstractIntegrationTest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 4, "Required tests":
 * every built-in fixture passes, a mocked forwarder/invoker/process-manager/HTTP-client/OAuth
 * service all see zero interactions during a run, and a malformed fixture fails closed to ERROR
 * without leaking the raw payload.
 */
@SpringBootTest
class EvaluationEngineIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private EvaluationSuiteService suiteService;
    @Autowired
    private EvaluationRunService runService;

    // "No GatewayRequest, no ToolForwarder, no MCP transport manager, no token acquisition" —
    // mock every one of these and prove a full run never touches any of them.
    @MockitoBean
    private ToolForwarder toolForwarder;
    @MockitoBean
    private McpToolInvoker mcpToolInvoker;
    @MockitoBean
    private StdioMcpProcessManager stdioMcpProcessManager;
    @MockitoBean
    private McpJsonRpcClient mcpJsonRpcClient;
    @MockitoBean
    private McpOAuthTokenService mcpOAuthTokenService;

    @Test
    void everyBuiltInFixtureEvaluatesAsIntendedAndTouchesNoForwardingInfrastructure() {
        EvaluationSuite suite = suiteService.createBuiltIn("test-admin");
        EvaluationRun run = runService.triggerRun(new TriggerRunRequest(suite.getName(), suite.getVersion()),
                "test-admin");
        List<EvaluationResult> results = runService.results(run.getId());
        Map<Long, EvaluationCase> casesById = suiteService.listCases(suite.getId()).stream()
                .collect(java.util.stream.Collectors.toMap(EvaluationCase::getId, c -> c));

        assertThat(results).hasSize(11);
        for (EvaluationResult result : results) {
            EvaluationCase evaluationCase = casesById.get(result.getCaseId());
            if (evaluationCase.getCaseKey().equals("malformed-context")) {
                assertThat(result.getResultStatus())
                        .as("malformed-context must fail closed, not silently pass")
                        .isEqualTo(EvaluationResultStatus.ERROR);
                assertThat(result.getRedactedReason()).doesNotContain("{ this is not valid JSON");
            } else {
                assertThat(result.getResultStatus())
                        .as("case '%s' should PASS against the shipped default policy", evaluationCase.getCaseKey())
                        .isEqualTo(EvaluationResultStatus.PASS);
            }
        }
        assertThat(run.getTotalCases()).isEqualTo(11);
        assertThat(run.getPassedCases()).isEqualTo(10);
        assertThat(run.getErrorCases()).isEqualTo(1);
        assertThat(run.getFailedCases()).isEqualTo(0);

        Mockito.verifyNoInteractions(toolForwarder, mcpToolInvoker, stdioMcpProcessManager, mcpJsonRpcClient,
                mcpOAuthTokenService);
    }

    @Test
    void aDeliberatelyWrongExpectationMakesTheCaseFailAndPreservesBothExpectedAndActual() {
        var wrongCase = new EvaluationDtos.CaseImport("deliberately-wrong",
                "{\"actionCategory\":\"READ\",\"targetEnvironment\":\"DEV\",\"toolApprovalStatus\":\"APPROVED\","
                        + "\"agentEnabled\":true,\"toolGroup\":\"db\",\"agentAllowedToolGroups\":\"db\"}",
                PolicyDecisionType.DENY, "deny-schema-drift", true, "regression");
        EvaluationSuite suite = suiteService.create(
                new EvaluationDtos.CreateSuiteRequest("wrong-expectation-suite-" + System.nanoTime(), null,
                        List.of(wrongCase)),
                "test-admin");

        EvaluationRun run = runService.triggerRun(new TriggerRunRequest(suite.getName(), suite.getVersion()),
                "test-admin");
        List<EvaluationResult> results = runService.results(run.getId());

        assertThat(results).hasSize(1);
        EvaluationResult result = results.get(0);
        assertThat(result.getResultStatus()).isEqualTo(EvaluationResultStatus.FAIL);
        // A genuinely safe read actually ALLOWs — the case wrongly expected DENY/deny-schema-drift.
        assertThat(result.getActualDecision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(result.getRedactedReason()).contains("DENY").contains("ALLOW").contains("deny-schema-drift");
    }
}
