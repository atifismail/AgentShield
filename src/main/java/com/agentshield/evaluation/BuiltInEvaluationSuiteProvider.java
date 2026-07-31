package com.agentshield.evaluation;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.TokenHasher;
import com.agentshield.grant.AgentToolGrant;
import com.agentshield.grant.AgentToolGrantRepository;
import com.agentshield.grant.GrantStatus;
import com.agentshield.grant.GrantTransitionMode;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * The shipped default suite, one case per required fixture category (work package 4, "Fixture
 * rules"): safe read, unknown tool, tool drift, missing grant, expired grant, wrong resource,
 * missing MCP consent, prod write, external transfer, DLP block, and malformed context.
 * {@code expired-grant}/{@code wrong-resource} need one real, persisted {@link Agent}/{@link Tool}
 * pair plus one real {@link AgentToolGrant} row each — {@code agent_tool_grants} has a real
 * foreign key to both tables, so an arbitrary unpersisted ID cannot be used there (unlike the
 * "missing grant"/"missing MCP consent" cases, which only ever trigger a {@code SELECT} against
 * an ID that is fine to leave nonexistent). {@link #ensureFixtures} seeds these idempotently by
 * name, the same architectural pattern {@code DemoDataSeeder} already uses for its own permanent
 * seed rows.
 */
@Component
public class BuiltInEvaluationSuiteProvider {

    public static final String SUITE_NAME = "built-in-default-policy";

    /** Deliberately out of range of any real IDENTITY-generated row — safe to leave nonexistent. */
    private static final long MISSING_GRANT_AGENT_ID = -9_005L;
    private static final long MISSING_GRANT_TOOL_ID = -9_006L;
    private static final long MISSING_MCP_SERVER_ID = -9_007L;

    private final AgentRepository agentRepository;
    private final ToolRepository toolRepository;
    private final AgentToolGrantRepository grantRepository;
    private final ObjectMapper objectMapper;

    public BuiltInEvaluationSuiteProvider(AgentRepository agentRepository, ToolRepository toolRepository,
            AgentToolGrantRepository grantRepository, ObjectMapper objectMapper) {
        this.agentRepository = agentRepository;
        this.toolRepository = toolRepository;
        this.grantRepository = grantRepository;
        this.objectMapper = objectMapper;
    }

    private record FixtureIds(long agentId, long toolId) {
    }

    /** Idempotent by name: safe to call every time the built-in suite is (re)created. */
    @Transactional
    private FixtureIds ensureFixture(String namePrefix) {
        Agent agent = agentRepository.findByName("eval-fixture-agent-" + namePrefix).orElseGet(() -> {
            Agent a = new Agent();
            a.setName("eval-fixture-agent-" + namePrefix);
            a.setStatus(AgentStatus.ENABLED);
            a.setOwner("evaluation-fixture-seed");
            return agentRepository.save(a);
        });
        Tool tool = toolRepository.findByName("eval-fixture-tool-" + namePrefix).orElseGet(() -> {
            Tool t = new Tool();
            t.setName("eval-fixture-tool-" + namePrefix);
            t.setType(ToolType.DATABASE);
            t.setToolGroup("db");
            t.setApprovalStatus(ToolApprovalStatus.APPROVED);
            String hash = TokenHasher.sha256Hex("eval-fixture-" + namePrefix);
            t.setApprovedHash(hash);
            t.setCurrentHash(hash);
            return toolRepository.save(t);
        });
        return new FixtureIds(agent.getId(), tool.getId());
    }

    @Transactional
    public void ensureAndSeedGrant(String namePrefix, java.util.function.Consumer<AgentToolGrant> customize) {
        FixtureIds ids = ensureFixture(namePrefix);
        if (grantRepository.findByAgentIdAndToolId(ids.agentId(), ids.toolId()).isEmpty()) {
            AgentToolGrant grant = new AgentToolGrant();
            grant.setAgentId(ids.agentId());
            grant.setToolId(ids.toolId());
            grant.setStatus(GrantStatus.ACTIVE);
            grant.setCreatedBy("evaluation-fixture-seed");
            grant.setReason("built-in evaluation suite fixture: " + namePrefix);
            customize.accept(grant);
            grantRepository.save(grant);
        }
    }

    /** Idempotent: safe to call every time the built-in suite is (re)created. Persists the two
     * fixture agent/tool/grant triples "expired-grant" and "wrong-resource" need. */
    @Transactional
    public void ensureGrantFixtures() {
        ensureAndSeedGrant("expired-grant", grant -> grant.setExpiresAt(Instant.now().minus(1, ChronoUnit.DAYS)));
        ensureAndSeedGrant("wrong-resource", grant -> grant.setResourcePathPattern("/repos/*/pulls"));
    }

    public List<EvaluationCaseSpec> buildCases() {
        FixtureIds expiredGrantIds = ensureFixture("expired-grant");
        FixtureIds wrongResourceIds = ensureFixture("wrong-resource");

        List<EvaluationCaseSpec> cases = new ArrayList<>();

        cases.add(spec("safe-read", "A routine, approved, in-group read is allowed.",
                new EvaluationCaseFixture(null, 1L, true, "db", 1L, "safe-read-tool", ToolApprovalStatus.APPROVED,
                        false, "db", null, null, null, ActionCategory.READ, "DEV", 10, null, null, null),
                PolicyDecisionType.ALLOW, null));

        cases.add(spec("unknown-tool", "A tool name the registry has never seen is denied, not silently ignored.",
                new EvaluationCaseFixture(true, null, null, null, null, null, null, null, null, null, null, null,
                        ActionCategory.READ, "DEV", 10, null, null, null),
                PolicyDecisionType.DENY, "deny-tool-not-registered"));

        cases.add(spec("tool-drift", "A tool whose fingerprint no longer matches its approved baseline is blocked.",
                new EvaluationCaseFixture(null, 2L, true, "db", 2L, "drifted-tool", ToolApprovalStatus.DRIFTED, true,
                        "db", null, null, null, ActionCategory.READ, "DEV", 10, null, null, null),
                PolicyDecisionType.DENY, "deny-schema-drift"));

        cases.add(spec("missing-grant", "GRANTS_REQUIRED with zero grants for the pair denies outright.",
                new EvaluationCaseFixture(null, MISSING_GRANT_AGENT_ID, true, "db", MISSING_GRANT_TOOL_ID,
                        "missing-grant-tool", ToolApprovalStatus.APPROVED, false, "db", null, null, null,
                        ActionCategory.READ, "DEV", 10, null, GrantTransitionMode.GRANTS_REQUIRED, null),
                PolicyDecisionType.DENY, "deny-no-matching-grant"));

        cases.add(spec("expired-grant", "A grant that exists but is past its expiresAt denies exactly like no grant.",
                new EvaluationCaseFixture(null, expiredGrantIds.agentId(), true, "db", expiredGrantIds.toolId(),
                        "expired-grant-tool", ToolApprovalStatus.APPROVED, false, "db", null, null, null,
                        ActionCategory.READ, "DEV", 10, null, GrantTransitionMode.GRANTS_REQUIRED, null),
                PolicyDecisionType.DENY, "deny-no-matching-grant"));

        cases.add(spec("wrong-resource",
                "A grant restricted by resource path never matches when no resource fact was established "
                        + "(release one ships no ToolAuthorizationNormalizer) — absence of the fact is never "
                        + "treated as satisfying the restriction.",
                new EvaluationCaseFixture(null, wrongResourceIds.agentId(), true, "db", wrongResourceIds.toolId(),
                        "wrong-resource-tool", ToolApprovalStatus.APPROVED, false, "db", null, null, null,
                        ActionCategory.READ, "DEV", 10, null, GrantTransitionMode.GRANTS_REQUIRED, null),
                PolicyDecisionType.DENY, "deny-no-matching-grant"));

        cases.add(spec("missing-mcp-consent", "An APPROVED MCP-backed tool with no consent grant is still denied.",
                new EvaluationCaseFixture(null, 3L, true, "mcp", 3L, "mcp-tool", ToolApprovalStatus.APPROVED, false,
                        "mcp", null, MISSING_MCP_SERVER_ID, "echo", ActionCategory.READ, "DEV", 10, null, null, null),
                PolicyDecisionType.DENY, "deny-missing-mcp-consent"));

        cases.add(spec("prod-write", "A production write always requires human approval.",
                new EvaluationCaseFixture(null, 4L, true, "db", 4L, "prod-write-tool", ToolApprovalStatus.APPROVED,
                        false, "db", null, null, null, ActionCategory.WRITE, "PROD", 10, null, null, null),
                PolicyDecisionType.APPROVAL_REQUIRED, "require-approval-prod-write"));

        cases.add(spec("external-transfer", "External data transfer always requires human approval.",
                new EvaluationCaseFixture(null, 5L, true, "saas", 5L, "external-tool", ToolApprovalStatus.APPROVED,
                        false, "saas", null, null, null, ActionCategory.EXTERNAL_TRANSFER, "DEV", 10, null, null,
                        null),
                PolicyDecisionType.APPROVAL_REQUIRED, "require-approval-external-transfer"));

        cases.add(spec("dlp-block", "A synthetic AWS-access-key-shaped string in the tool argument is blocked by DLP.",
                new EvaluationCaseFixture(null, 6L, true, "db", 6L, "dlp-tool", ToolApprovalStatus.APPROVED, false,
                        "db", null, null, null, ActionCategory.READ, "DEV", 10, null, null,
                        "aws_secret_access_key=AKIAABCDEFGHIJKLMNOP"),
                PolicyDecisionType.DENY, "deny-dlp-block"));

        // Deliberately invalid JSON — proves the engine fails closed to ERROR instead of a silent
        // PASS/ALLOW, and never echoes the raw (here, malformed) fixture payload in its result.
        cases.add(new EvaluationCaseSpec("malformed-context", "{ this is not valid JSON",
                PolicyDecisionType.DENY, null));

        return cases;
    }

    private EvaluationCaseSpec spec(String key, String description, EvaluationCaseFixture fixture,
            PolicyDecisionType expectedDecision, String expectedRuleId) {
        try {
            String json = objectMapper.writeValueAsString(fixture);
            return new EvaluationCaseSpec(key, json, expectedDecision, expectedRuleId);
        } catch (Exception e) {
            throw new IllegalStateException("built-in evaluation fixture '" + key + "' failed to serialize", e);
        }
    }

    public record EvaluationCaseSpec(String caseKey, String inputFixtureJson, PolicyDecisionType expectedDecision,
            String expectedRuleId) {
    }
}
