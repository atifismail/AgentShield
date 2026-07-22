package com.agentshield.siem;

import com.agentshield.approval.ApprovalService;
import com.agentshield.codetrust.AssessmentSource;
import com.agentshield.codetrust.CodeAssessment;
import com.agentshield.codetrust.CodeAssessmentService;
import com.agentshield.codetrust.CodeTrustDtos.FindingRequest;
import com.agentshield.codetrust.CodeTrustDtos.SubmitAssessmentRequest;
import com.agentshield.codetrust.FindingCategory;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.RiskLevel;
import com.agentshield.common.ValidationException;
import com.agentshield.dlp.ContentStage;
import com.agentshield.dlp.DlpAction;
import com.agentshield.dlp.DlpScanResult;
import com.agentshield.dlp.DlpScanService;
import com.agentshield.gateway.GatewayDtos.InvokeRequest;
import com.agentshield.gateway.GatewayDtos.InvokeResponse;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.gateway.GatewayService;
import com.agentshield.mcp.McpDiscoveryService;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.mcp.McpTransportType;
import com.agentshield.policy.PolicyDecisionRepository;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolProvenanceService;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

/**
 * Replays the 10 original attack scenarios from {@code docs/demo-lab.md} /
 * {@code scripts/demo-attack-lab.sh}, plus 2 more added for the SOC Validation Module
 * (improvement_plan.md N1, folded into AgentShield): RAG data leakage (scenario-11) and an AI
 * coding assistant introducing a secret (scenario-12). All run in-process (direct service calls,
 * not HTTP-against-self) against the seeded demo agents/tools
 * ({@code com.agentshield.demo.DemoDataSeeder}), asserting the expected {@link DetectionRule}
 * fired for each — a Java-side, assertable, repeatable counterpart to the manual curl walkthrough.
 *
 * <p><b>A 13th scenario, MCP token misuse (scenario-10), deliberately does not appear in this
 * class or {@link #runAll()}.</b> It genuinely requires the test-only mock OAuth/MCP server
 * infrastructure ({@code com.agentshield.support.MockOAuthServerController}, {@code src/test}) to
 * produce a real wrong-audience token to reject — that infrastructure does not exist in
 * {@code src/main} and should not be added there just for this (it would mean shipping mock
 * authorization-server endpoints in every real deployment, demo profile included). Scenario-10 is
 * instead a dedicated JUnit test, {@code McpTokenMisuseAttackScenarioTest}, which mirrors
 * {@code McpOAuthTokenServiceTest}'s existing wrong-audience setup and records its own
 * {@link DetectionValidationRun} row — so it still shows up in the coverage/validation dashboards,
 * just not reachable via the live {@code POST /api/siem/validate} /
 * {@code POST /api/siem/validation/scenarios/run} endpoints alongside the other 12.
 *
 * <p>A 14th scenario from the original N1 plan, certificate-expiry-near-miss, is intentionally
 * not implemented at all — see {@code docs/demo-lab.md} and {@code README.md} for why (it is a
 * TrustAtlas concept; this codebase has no certificate management).
 */
@Service
public class AttackSimulatorService {

    public record ScenarioResult(String scenarioCode, String description, boolean passed,
            String expectedDetectionRuleCode, String detail) {
    }

    /** One row of the scenario catalog, for pages/reports that need to list every scenario
     * (including ones with no rule to join against, like scenario-8/9) rather than only ones a
     * {@link DetectionRule} row already exists for. */
    public record ScenarioCatalogEntry(String code, String description, String expectedDetectionRuleCode) {
    }

    /** Source of truth for the SOC Validation dashboard's scenario-coverage table — kept separate
     * from the scenario methods below (rather than derived from them) since a description needs
     * to be available even for a scenario that has never been run yet. */
    public static final List<ScenarioCatalogEntry> SCENARIO_CATALOG = List.of(
            new ScenarioCatalogEntry("scenario-0", "Baseline allowed call (mock-git commit)", null),
            new ScenarioCatalogEntry("scenario-1", "Tool schema drift is detected and blocked", "deny-schema-drift"),
            new ScenarioCatalogEntry("scenario-2", "Production destructive action is denied outright",
                    "deny-prod-destructive-without-approval"),
            new ScenarioCatalogEntry("scenario-3", "Secret-like response is blocked (after approval, on execution)",
                    "deny-secret-external-transfer"),
            new ScenarioCatalogEntry("scenario-4", "Prompt-injected tool response is blocked",
                    "deny-prompt-injection-response"),
            new ScenarioCatalogEntry("scenario-5", "External transfer requires human approval",
                    "require-approval-external-transfer"),
            new ScenarioCatalogEntry("scenario-6", "Tool misuse outside the agent's allowed group",
                    "deny-tool-outside-allowed-group"),
            new ScenarioCatalogEntry("scenario-7", "A disabled agent's cryptographically valid credential is rejected",
                    "deny-disabled-agent"),
            new ScenarioCatalogEntry("scenario-8", "Every tool version gets an automatic supply-chain provenance record",
                    null),
            new ScenarioCatalogEntry("scenario-9", "Unexpected code execution attempt — stdio closed by default", null),
            new ScenarioCatalogEntry("scenario-10", "MCP OAuth token misuse (wrong audience) is rejected — see "
                    + "McpTokenMisuseAttackScenarioTest, not runAll()", "mcp-oauth-token-rejected"),
            new ScenarioCatalogEntry("scenario-11", "Data leakage through RAG output is blocked/redacted",
                    "deny-dlp-block"),
            new ScenarioCatalogEntry("scenario-12", "AI coding assistant introduces a secret — assessment blocked",
                    "codetrust-blocked"));

    private static final String CODING_AGENT_TOKEN = "demo-token-coding-agent-01";
    private static final String SUPPORT_AGENT_TOKEN = "demo-token-support-assistant-01";
    private static final String RETIRED_AGENT_TOKEN = "demo-token-retired-agent-01";
    private static final String TRIGGERED_BY = "attack-simulator";

    private final GatewayService gatewayService;
    private final ApprovalService approvalService;
    private final ToolService toolService;
    private final ToolRepository toolRepository;
    private final ToolProvenanceService toolProvenanceService;
    private final McpDiscoveryService mcpDiscoveryService;
    private final GatewayRequestRepository gatewayRequestRepository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final DetectionValidationRunRepository validationRunRepository;
    private final DlpScanService dlpScanService;
    private final CodeAssessmentService codeAssessmentService;
    private final ObjectMapper objectMapper;

    public AttackSimulatorService(GatewayService gatewayService, ApprovalService approvalService,
            ToolService toolService, ToolRepository toolRepository, ToolProvenanceService toolProvenanceService,
            McpDiscoveryService mcpDiscoveryService, GatewayRequestRepository gatewayRequestRepository,
            PolicyDecisionRepository policyDecisionRepository,
            DetectionValidationRunRepository validationRunRepository, DlpScanService dlpScanService,
            CodeAssessmentService codeAssessmentService, ObjectMapper objectMapper) {
        this.gatewayService = gatewayService;
        this.approvalService = approvalService;
        this.toolService = toolService;
        this.toolRepository = toolRepository;
        this.toolProvenanceService = toolProvenanceService;
        this.mcpDiscoveryService = mcpDiscoveryService;
        this.gatewayRequestRepository = gatewayRequestRepository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.validationRunRepository = validationRunRepository;
        this.dlpScanService = dlpScanService;
        this.codeAssessmentService = codeAssessmentService;
        this.objectMapper = objectMapper;
    }

    public List<ScenarioResult> runAll() {
        List<ScenarioResult> results = new ArrayList<>();
        results.add(scenario0BaselineAllow());
        results.add(scenario1SchemaDrift());
        results.add(scenario2ProdDestructiveDenied());
        results.add(scenario3SecretResponseBlocked());
        results.add(scenario4PromptInjectionBlocked());
        results.add(scenario5ExternalTransferApproval());
        results.add(scenario6ToolMisuse());
        results.add(scenario7DisabledAgent());
        results.add(scenario8SupplyChainProvenance());
        results.add(scenario9StdioClosedByDefault());
        results.add(scenario11RagDataLeakage());
        results.add(scenario12CodeAssistantIntroducesSecret());
        results.forEach(this::persist);
        return results;
    }

    private ScenarioResult scenario0BaselineAllow() {
        InvokeResponse response = invoke(CODING_AGENT_TOKEN, "mock-git", "commit", ActionCategory.WRITE, "DEV",
                Map.of("message", "demo commit"));
        boolean passed = response.decision() == PolicyDecisionType.ALLOW;
        return new ScenarioResult("scenario-0", "Baseline allowed call (mock-git commit)", passed, null,
                "decision=" + response.decision());
    }

    private ScenarioResult scenario1SchemaDrift() {
        Tool tool = requireTool("mock-git");
        // The "changed" schema must differ from whatever is *currently* approved, not just from
        // the original seed — this scenario (and this whole test suite) shares one long-lived
        // demo database across many runAll() calls (this class's own two tests, plus any other
        // test class that also calls runAll(), e.g. SiemExportIntegrationTest), and the previous
        // call's re-approve step (below) makes the fixed schema string it used the new approved
        // baseline. A fixed literal here would only ever be detected as drift on the very first
        // call in the whole suite; every later call would see "no change from approved" and
        // silently degrade to ALLOW. A nanoTime-suffixed schema guarantees drift is detected every
        // single time, independent of call count or test execution order.
        toolService.refreshFingerprint(tool.getId(),
                "{\"actions\":[\"commit\",\"push\",\"createBranch\",\"forcePush\"],\"rev\":" + System.nanoTime() + "}",
                "Mock Git tool (schema changed)");
        InvokeResponse response = invoke(CODING_AGENT_TOKEN, "mock-git", "commit", ActionCategory.WRITE, "DEV",
                Map.of("message", "demo commit"));
        // Restore approved state so later scenarios/tests that depend on mock-git being APPROVED
        // aren't affected by this scenario running — mirrors demo-attack-lab.sh's own re-approve step.
        toolService.approveLatestVersion(tool.getId(), TRIGGERED_BY);
        String firedRule = lastFiredRuleIdFor(CODING_AGENT_TOKEN).orElse(null);
        boolean passed = response.decision() == PolicyDecisionType.DENY
                && "deny-schema-drift".equals(firedRule);
        return new ScenarioResult("scenario-1", "Tool schema drift is detected and blocked", passed,
                "deny-schema-drift", "decision=" + response.decision() + " rule=" + firedRule);
    }

    private ScenarioResult scenario2ProdDestructiveDenied() {
        InvokeResponse response = invoke(CODING_AGENT_TOKEN, "mock-database", "deleteRecords",
                ActionCategory.DESTRUCTIVE, "PROD", Map.of("table", "users", "where", "status = 'inactive'"));
        String firedRule = lastFiredRuleIdFor(CODING_AGENT_TOKEN).orElse(null);
        boolean passed = response.decision() == PolicyDecisionType.DENY
                && "deny-prod-destructive-without-approval".equals(firedRule);
        return new ScenarioResult("scenario-2", "Production destructive action is denied outright", passed,
                "deny-prod-destructive-without-approval", "decision=" + response.decision() + " rule=" + firedRule);
    }

    private ScenarioResult scenario3SecretResponseBlocked() {
        InvokeResponse first = invoke(CODING_AGENT_TOKEN, "mock-database", "query", ActionCategory.EXTERNAL_TRANSFER,
                "DEV", Map.of("table", "internal_credentials"));
        if (first.decision() != PolicyDecisionType.APPROVAL_REQUIRED || first.approvalRequestId() == null) {
            return new ScenarioResult("scenario-3", "Secret-like response is blocked (after approval, on execution)",
                    false, "deny-secret-external-transfer", "expected APPROVAL_REQUIRED, got " + first.decision());
        }
        approvalService.approve(first.approvalRequestId(), TRIGGERED_BY);
        String firedRule = lastFiredRuleIdFor(CODING_AGENT_TOKEN).orElse(null);
        boolean passed = "deny-secret-external-transfer".equals(firedRule);
        return new ScenarioResult("scenario-3", "Secret-like response is blocked (after approval, on execution)",
                passed, "deny-secret-external-transfer", "post-approval rule=" + firedRule);
    }

    private ScenarioResult scenario4PromptInjectionBlocked() {
        InvokeResponse response = invoke(CODING_AGENT_TOKEN, "mock-filesystem", "readFile", ActionCategory.READ,
                "DEV", Map.of("path", "notes/shared-todo.txt"));
        String firedRule = lastFiredRuleIdFor(CODING_AGENT_TOKEN).orElse(null);
        boolean passed = response.decision() == PolicyDecisionType.DENY
                && "deny-prompt-injection-response".equals(firedRule);
        return new ScenarioResult("scenario-4", "Prompt-injected tool response is blocked", passed,
                "deny-prompt-injection-response", "decision=" + response.decision() + " rule=" + firedRule);
    }

    private ScenarioResult scenario5ExternalTransferApproval() {
        InvokeResponse response = invoke(SUPPORT_AGENT_TOKEN, "mock-saas-crm", "exportRecords",
                ActionCategory.EXTERNAL_TRANSFER, "PROD", Map.of("segment", "all-customers"));
        String firedRule = lastFiredRuleIdFor(SUPPORT_AGENT_TOKEN).orElse(null);
        boolean passed = response.decision() == PolicyDecisionType.APPROVAL_REQUIRED
                && "require-approval-external-transfer".equals(firedRule);
        return new ScenarioResult("scenario-5", "External transfer requires human approval", passed,
                "require-approval-external-transfer", "decision=" + response.decision() + " rule=" + firedRule);
    }

    private ScenarioResult scenario6ToolMisuse() {
        InvokeResponse response = invoke(SUPPORT_AGENT_TOKEN, "mock-git", "push", ActionCategory.WRITE, "DEV",
                Map.of());
        String firedRule = lastFiredRuleIdFor(SUPPORT_AGENT_TOKEN).orElse(null);
        boolean passed = response.decision() == PolicyDecisionType.DENY
                && "deny-tool-outside-allowed-group".equals(firedRule);
        return new ScenarioResult("scenario-6", "Tool misuse outside the agent's allowed group", passed,
                "deny-tool-outside-allowed-group", "decision=" + response.decision() + " rule=" + firedRule);
    }

    private ScenarioResult scenario7DisabledAgent() {
        InvokeResponse response = invoke(RETIRED_AGENT_TOKEN, "mock-filesystem", "readFile", ActionCategory.READ,
                "DEV", Map.of("path", "notes/shared-todo.txt"));
        String firedRule = lastFiredRuleIdFor(RETIRED_AGENT_TOKEN).orElse(null);
        boolean passed = response.decision() == PolicyDecisionType.DENY && "deny-disabled-agent".equals(firedRule);
        return new ScenarioResult("scenario-7", "A disabled agent's cryptographically valid credential is rejected",
                passed, "deny-disabled-agent", "decision=" + response.decision() + " rule=" + firedRule);
    }

    private ScenarioResult scenario8SupplyChainProvenance() {
        Tool tool = requireTool("mock-git");
        boolean passed = toolProvenanceService.latestForTool(tool.getId()).isPresent();
        return new ScenarioResult("scenario-8", "Every tool version gets an automatic supply-chain provenance record",
                passed, null, "provenance present=" + passed);
    }

    private ScenarioResult scenario9StdioClosedByDefault() {
        RegisterMcpServerRequest request = new RegisterMcpServerRequest("attempted-stdio-server-" + System.nanoTime(),
                McpTransportType.STDIO, null, "bash", "-c \"echo pwned\"", null, null, "DEV", "mcp");
        boolean passed;
        String detail;
        try {
            mcpDiscoveryService.register(request);
            passed = false;
            detail = "expected registration to be rejected, but it succeeded";
        } catch (ValidationException e) {
            passed = e.getMessage() != null && e.getMessage().contains("stdio transport is disabled");
            detail = e.getMessage();
        }
        return new ScenarioResult("scenario-9", "Unexpected code execution attempt — stdio closed by default",
                passed, null, detail);
    }

    /** N1 scenario: "data leakage through RAG output" — a RAG chunk containing a secret-like
     * pattern must not be classified ALLOW by {@link DlpScanService}. Uses an AWS-access-key-shaped
     * string ({@code SecretDetector}'s {@code AKIA[0-9A-Z]{16}} pattern) since it is deterministic
     * and needs no live external service, unlike the MCP-OAuth scenario (see class javadoc). */
    private ScenarioResult scenario11RagDataLeakage() {
        String plantedSecretChunk = "Deployment notes: prod access key is AKIAABCDEFGHIJKLMNOP, rotate quarterly.";
        DlpScanResult result = dlpScanService.scan(plantedSecretChunk, ContentStage.RAG_CHUNK,
                "attack-simulator-scenario-11");
        boolean passed = result.action() == DlpAction.BLOCK || result.action() == DlpAction.REDACT;
        return new ScenarioResult("scenario-11", "Data leakage through RAG output is blocked/redacted", passed,
                "deny-dlp-block", "action=" + result.action());
    }

    /** N1 scenario: "AI coding assistant introduces a secret" — a submitted code assessment with a
     * planted HIGH-severity SECRET finding must be BLOCKED, and no {@link com.agentshield.codetrust.AiCodeReceipt}
     * issued for it. */
    private ScenarioResult scenario12CodeAssistantIntroducesSecret() {
        var findingRequest = new FindingRequest("src/main/java/com/example/Config.java", 42, FindingCategory.SECRET,
                RiskLevel.HIGH, "planted-secret-demo", "hardcoded credential planted by attack-simulator");
        var request = new SubmitAssessmentRequest("attack-simulator/demo-repo",
                "sha-" + System.nanoTime(), "main", "ai-assistant", AssessmentSource.CI, false, TRIGGERED_BY,
                List.of(findingRequest));
        CodeAssessment assessment = codeAssessmentService.submit(request);
        boolean blocked = assessment.getStatus() == com.agentshield.codetrust.AssessmentStatus.BLOCKED;
        boolean noReceiptIssued = codeAssessmentService.receiptFor(assessment.getId()).isEmpty();
        boolean passed = blocked && noReceiptIssued;
        return new ScenarioResult("scenario-12", "AI coding assistant introduces a secret — assessment blocked",
                passed, "codetrust-blocked", "status=" + assessment.getStatus() + " receiptIssued=" + !noReceiptIssued);
    }

    private InvokeResponse invoke(String token, String toolName, String action, ActionCategory category,
            String environment, Map<String, Object> inputMap) {
        JsonNode input = objectMapper.valueToTree(inputMap);
        InvokeRequest request = new InvokeRequest(null, toolName, action, category, environment, input,
                Map.of("userId", TRIGGERED_BY));
        return gatewayService.invoke(token, request);
    }

    /** Resolves which policy rule ultimately fired for the most recent gateway request made under
     * the given token's agent — {@code InvokeResponse} itself doesn't carry the rule id, only the
     * human-readable reason, so this reads the {@code PolicyDecision} row back directly. Works for
     * both a single-decision call and the two-decision approve-then-block sequence (scenario 3),
     * since it always returns the latest decision by {@code createdAt} for that gateway request.
     *
     * <p>Sorts by {@code createdAt DESC, id DESC} (not {@code createdAt} alone): the same agent
     * (e.g. {@code support-assistant-01}, used back-to-back by scenarios 5 and 6) can produce two
     * {@code GatewayRequest} rows within the same wall-clock second — MariaDB's {@code TIMESTAMP}
     * column here has second, not sub-second, resolution — and without an id tiebreak the "most
     * recent" row is nondeterministic under that tie. Same root cause and fix as
     * {@code PolicyDecisionRepository.findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc}. */
    private Optional<String> lastFiredRuleIdFor(String token) {
        Long agentId = gatewayService.authenticate(token).getId();
        var sort = Sort.by(Sort.Direction.DESC, "createdAt").and(Sort.by(Sort.Direction.DESC, "id"));
        return gatewayRequestRepository.findByAgentIdOrderByCreatedAtDesc(agentId, PageRequest.of(0, 1, sort))
                .stream().findFirst()
                .flatMap(gr -> policyDecisionRepository.findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc(gr.getId()))
                .map(com.agentshield.policy.PolicyDecision::getRuleId);
    }

    private Tool requireTool(String name) {
        return toolRepository.findByName(name)
                .orElseThrow(() -> new IllegalStateException("demo tool '" + name + "' not seeded — is the 'demo' profile active?"));
    }

    private void persist(ScenarioResult result) {
        DetectionValidationRun run = new DetectionValidationRun();
        run.setScenarioCode(result.scenarioCode());
        run.setDetectionRuleCode(result.expectedDetectionRuleCode());
        run.setPassed(result.passed());
        run.setDetail(result.detail());
        run.setTriggeredBy(TRIGGERED_BY);
        validationRunRepository.save(run);
    }
}
