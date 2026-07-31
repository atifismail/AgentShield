package com.agentshield.grant;

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
import com.agentshield.mcp.McpConsentDtos.CreateConsentRequest;
import com.agentshield.mcp.McpConsentService;
import com.agentshield.mcp.McpDiscoveryService;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.mcp.McpServer;
import com.agentshield.mcp.McpTransportType;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockMcpServerController;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 2, end-to-end "Required
 * tests" through the real gateway pipeline with {@code GRANTS_REQUIRED} active — a separate Spring
 * context from the rest of the suite (via {@code @TestPropertySource}), so this never touches the
 * default {@code GROUPS_ONLY} behavior every other test relies on.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "agentshield.grants.transition-mode=GRANTS_REQUIRED")
class AgentToolGrantGatewayIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private AgentToolGrantRepository grantRepository;
    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpConsentService consentService;
    @Autowired
    private ObjectMapper objectMapper;

    private final TestRestTemplate restTemplate = new TestRestTemplate();

    @BeforeEach
    void resetMockServer() {
        MockMcpServerController.echoToolDescription.set("Echoes its input");
        MockMcpServerController.includeSecondTool.set(true);
        MockMcpServerController.requiredBearerToken.set(null);
    }

    private record Fixture(Agent agent, String plaintextToken, Tool tool) {
    }

    private Fixture setUpAgentAndApprovedTool(String toolGroup) {
        Tool tool = new Tool();
        tool.setName("grants-required-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup(toolGroup);
        tool.setEndpointUrl("http://localhost:" + port + "/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        String hash = TokenHasher.sha256Hex("schema+desc");
        tool.setApprovedHash(hash);
        tool.setCurrentHash(hash);
        tool = toolRepository.save(tool);

        // In the group, to prove GRANTS_REQUIRED ignores that entirely without a matching grant.
        Agent agent = new Agent();
        agent.setName("grants-required-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups(toolGroup);
        agent = agentRepository.save(agent);

        String plaintextToken = "grants-required-token-" + System.nanoTime();
        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        return new Fixture(agent, plaintextToken, tool);
    }

    private GatewayDtos.InvokeResponse invoke(Fixture fixture, ActionCategory actionCategory, String environment) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", fixture.tool().getName());
        body.put("action", "read");
        body.put("actionCategory", actionCategory.name());
        body.put("targetEnvironment", environment);
        body.set("input", objectMapper.createObjectNode());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + fixture.plaintextToken());

        return restTemplate.exchange("http://localhost:" + port + "/api/gateway/invoke", HttpMethod.POST,
                new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
    }

    private AgentToolGrant activeGrant(Fixture fixture, ActionCategory actionCategory, String environment) {
        AgentToolGrant grant = new AgentToolGrant();
        grant.setAgentId(fixture.agent().getId());
        grant.setToolId(fixture.tool().getId());
        grant.setStatus(GrantStatus.ACTIVE);
        grant.setActionCategory(actionCategory);
        grant.setTargetEnvironment(environment);
        return grantRepository.save(grant);
    }

    @Test
    void noGrantAtAllDeniesEvenThoughTheAgentIsInTheAllowedGroup() {
        Fixture fixture = setUpAgentAndApprovedTool("db");

        var response = invoke(fixture, ActionCategory.READ, "DEV");

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.reason()).contains("no matching active grant");
    }

    @Test
    void exactMatchingActiveGrantAllows() {
        Fixture fixture = setUpAgentAndApprovedTool("db");
        activeGrant(fixture, ActionCategory.READ, "DEV");

        var response = invoke(fixture, ActionCategory.READ, "DEV");

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void grantForADifferentActionCategoryDenies() {
        Fixture fixture = setUpAgentAndApprovedTool("db");
        activeGrant(fixture, ActionCategory.WRITE, "DEV");

        var response = invoke(fixture, ActionCategory.READ, "DEV");

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
    }

    @Test
    void grantForADifferentEnvironmentDenies() {
        Fixture fixture = setUpAgentAndApprovedTool("db");
        activeGrant(fixture, ActionCategory.READ, "PROD");

        var response = invoke(fixture, ActionCategory.READ, "DEV");

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
    }

    @Test
    void revokedGrantDenies() {
        Fixture fixture = setUpAgentAndApprovedTool("db");
        AgentToolGrant grant = activeGrant(fixture, ActionCategory.READ, "DEV");
        grant.setStatus(GrantStatus.REVOKED);
        grantRepository.saveAndFlush(grant);

        var response = invoke(fixture, ActionCategory.READ, "DEV");

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
    }

    @Test
    void anEarlierAllowedCallIsDeniedOnTheNextInvocationAfterTheGrantIsRevoked() {
        Fixture fixture = setUpAgentAndApprovedTool("db");
        AgentToolGrant grant = activeGrant(fixture, ActionCategory.READ, "DEV");

        assertThat(invoke(fixture, ActionCategory.READ, "DEV").decision()).isEqualTo(PolicyDecisionType.ALLOW);

        grant.setStatus(GrantStatus.REVOKED);
        grantRepository.saveAndFlush(grant);

        assertThat(invoke(fixture, ActionCategory.READ, "DEV").decision()).isEqualTo(PolicyDecisionType.DENY);
    }

    @Test
    void expiredGrantDenies() {
        Fixture fixture = setUpAgentAndApprovedTool("db");
        AgentToolGrant grant = activeGrant(fixture, ActionCategory.READ, "DEV");
        grant.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
        grantRepository.saveAndFlush(grant);

        var response = invoke(fixture, ActionCategory.READ, "DEV");

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
    }

    @Test
    void notYetActiveFutureGrantDenies() {
        Fixture fixture = setUpAgentAndApprovedTool("db");
        AgentToolGrant grant = activeGrant(fixture, ActionCategory.READ, "DEV");
        grant.setNotBefore(Instant.now().plus(1, ChronoUnit.HOURS));
        grantRepository.saveAndFlush(grant);

        var response = invoke(fixture, ActionCategory.READ, "DEV");

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
    }

    @Test
    void mcpConsentIsStillRequiredAfterAGrantAllowsAnMcpBackedTool() {
        McpServer server = discoveryService.register(new RegisterMcpServerRequest(
                "grants-required-mcp-" + System.nanoTime(), McpTransportType.HTTP,
                "http://localhost:" + port + "/demo/mock-mcp-server", null, null, null, "owner", "DEV", "mcp"));
        discoveryService.discover(server.getId());
        Tool echoTool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();
        echoTool.setApprovedHash(echoTool.getCurrentHash());
        echoTool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        toolRepository.saveAndFlush(echoTool);

        Agent agent = new Agent();
        agent.setName("grants-required-mcp-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent = agentRepository.save(agent);
        String plaintextToken = "grants-required-mcp-token-" + System.nanoTime();
        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);
        Fixture fixture = new Fixture(agent, plaintextToken, echoTool);

        AgentToolGrant grant = new AgentToolGrant();
        grant.setAgentId(agent.getId());
        grant.setToolId(echoTool.getId());
        grant.setStatus(GrantStatus.ACTIVE);
        grantRepository.save(grant);

        // Grant alone: still no MCP consent granted yet, so the confused-deputy gate must still deny.
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", echoTool.getName());
        body.put("action", "echo");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("message", "hi"));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);
        var withoutConsent = restTemplate.exchange("http://localhost:" + port + "/api/gateway/invoke",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
        assertThat(withoutConsent.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(withoutConsent.reason()).contains("no active MCP consent");

        // Now grant MCP consent too — only then should the call succeed.
        consentService.create(new CreateConsentRequest(agent.getId(), server.getId(), null, null, null),
                "security-analyst-1");
        var withConsent = restTemplate.exchange("http://localhost:" + port + "/api/gateway/invoke",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
        assertThat(withConsent.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }
}
