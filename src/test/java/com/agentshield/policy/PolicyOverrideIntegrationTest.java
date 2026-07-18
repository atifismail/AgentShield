package com.agentshield.policy;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.TokenHasher;
import com.agentshield.gateway.GatewayDtos;
import com.agentshield.policy.PolicyOverrideDtos.CreateOverrideRequest;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PolicyOverrideIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private PolicyOverrideService overrideService;
    @Autowired
    private PolicyOverrideRepository overrideRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private String plaintextToken;

    private Agent createAgent(String... groups) {
        plaintextToken = "override-test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("override-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups(String.join(",", groups));
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);
        return agent;
    }

    private Tool createTool(String group) {
        Tool tool = new Tool();
        tool.setName("override-test-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup(group);
        tool.setEndpointUrl("/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setApprovedHash("h");
        tool.setCurrentHash("h");
        return toolRepository.save(tool);
    }

    private GatewayDtos.InvokeResponse invoke(Agent agent, Tool tool, ActionCategory category, String env) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "doSomething");
        body.put("actionCategory", category.name());
        body.put("targetEnvironment", env);
        body.set("input", objectMapper.createObjectNode());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);

        return new TestRestTemplate().exchange("http://localhost:" + port + "/api/gateway/invoke", HttpMethod.POST,
                new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
    }

    @Test
    void overrideAddsExtraDenyWhereFixedRulesWouldAllow() {
        Agent agent = createAgent("database");
        Tool tool = createTool("database");

        // Baseline: a plain READ/DEV call has no fixed rule against it, so it's ALLOWed.
        assertThat(invoke(agent, tool, ActionCategory.READ, "DEV").decision()).isEqualTo(PolicyDecisionType.ALLOW);

        // Scoped to this test's own agent by name — an unscoped override would match every other
        // test's READ/DEV/"database" traffic too, since overrides persist for real (no rollback)
        // in the database this whole suite shares.
        overrideService.create(new CreateOverrideRequest(ActionCategory.READ, "DEV", "database", agent.getName(),
                PolicyDecisionType.DENY, "temporary freeze on database reads for maintenance", null), "security-analyst");

        var response = invoke(agent, tool, ActionCategory.READ, "DEV");
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.reason()).contains("maintenance");
    }

    @Test
    void overrideNeverBypassesAFixedSafetyRule() {
        Agent agent = createAgent("database");
        agent.setStatus(AgentStatus.DISABLED);
        agentRepository.saveAndFlush(agent);
        Tool tool = createTool("database");

        // An override that would ALLOW everything must not undo "deny disabled agent".
        overrideService.create(new CreateOverrideRequest(null, null, null, agent.getName(),
                PolicyDecisionType.ALLOW, "trusted test agent, allow everything", null), "security-analyst");

        var response = invoke(agent, tool, ActionCategory.READ, "DEV");
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.reason()).contains("disabled");
    }

    @Test
    void disabledOverrideIsIgnored() {
        Agent agent = createAgent("database");
        Tool tool = createTool("database");

        var override = overrideService.create(new CreateOverrideRequest(ActionCategory.READ, "DEV", "database",
                agent.getName(), PolicyDecisionType.DENY, "should not apply once disabled", null), "security-analyst");
        overrideService.setEnabled(override.getId(), false, "security-analyst");

        var response = invoke(agent, tool, ActionCategory.READ, "DEV");
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void matchesRequiresEveryNonNullFieldToAgree() {
        Agent agent = createAgent("database");
        Tool tool = createTool("database");
        PolicyEvaluationContext ctx = new PolicyEvaluationContext(agent, tool, ActionCategory.READ, "DEV", 10, 1000);

        PolicyOverride wrongEnvironment = new PolicyOverride();
        wrongEnvironment.setEnabled(true);
        wrongEnvironment.setTargetEnvironment("PROD");
        assertThat(wrongEnvironment.matches(ctx)).isFalse();

        PolicyOverride matchesEverything = new PolicyOverride();
        matchesEverything.setEnabled(true);
        assertThat(matchesEverything.matches(ctx)).isTrue();
    }
}
