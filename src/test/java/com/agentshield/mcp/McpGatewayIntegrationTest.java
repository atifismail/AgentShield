package com.agentshield.mcp;

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
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.mcp.McpDtos.UpdateMcpAuthRequest;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockMcpServerController;
import com.agentshield.support.MockOAuthServerController;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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

/**
 * Proves a discovered MCP tool flows through the exact same gateway/policy/audit pipeline as a
 * plain HTTP tool, and — since design-mcp-authorization.md — that MCP consent is now a required
 * additional gate: an APPROVED MCP tool alone is no longer sufficient (improvement_plan.md P1,
 * "MCP Authorization And Confused-Deputy Controls Are Missing").
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpGatewayIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpConsentService consentService;
    @Autowired
    private McpOAuthTokenService oauthTokenService;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private record Fixture(Agent agent, String plaintextToken, Tool tool, McpServer server) {
    }

    @BeforeEach
    void resetMockServer() {
        MockMcpServerController.echoToolDescription.set("Echoes its input");
        MockMcpServerController.includeSecondTool.set(true);
        MockMcpServerController.requiredBearerToken.set(null);
        MockOAuthServerController.reset();
    }

    private Fixture setUpAgentToolAndServer() {
        McpServer server = discoveryService.register(new RegisterMcpServerRequest(
                "mcp-gateway-test-" + System.nanoTime(), McpTransportType.HTTP,
                "http://localhost:" + port + "/demo/mock-mcp-server", null, null, null, "owner", "DEV", "mcp"));
        discoveryService.discover(server.getId());

        Tool echoTool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();
        echoTool.setApprovedHash(echoTool.getCurrentHash());
        echoTool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        toolRepository.saveAndFlush(echoTool);

        String plaintextToken = "mcp-test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("mcp-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("mcp");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        return new Fixture(agent, plaintextToken, echoTool, server);
    }

    private GatewayDtos.InvokeResponse invokeEcho(Fixture fixture) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", fixture.tool().getName());
        body.put("action", "echo");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("message", "hello via mcp"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + fixture.plaintextToken());

        return new TestRestTemplate().exchange("http://localhost:" + port + "/api/gateway/invoke",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
    }

    @Test
    void gatewayInvokeThroughAnMcpToolWorksEndToEndWithConsentGranted() {
        Fixture fixture = setUpAgentToolAndServer();
        consentService.create(new CreateConsentRequest(fixture.agent().getId(), fixture.server().getId(), null, null,
                null), "security-analyst-1");

        var response = invokeEcho(fixture);

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.result().get("toolName").asText()).isEqualTo("echo");
        assertThat(response.result().get("echoedArguments").get("message").asText()).isEqualTo("hello via mcp");
    }

    @Test
    void agentWithoutAnyConsentGrantIsDeniedEvenThoughTheToolIsApproved() {
        Fixture fixture = setUpAgentToolAndServer();
        // No consentService.create(...) call — this is the direct confused-deputy regression test.

        var response = invokeEcho(fixture);

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.reason()).contains("no active MCP consent");
    }

    @Test
    void consentScopedToADifferentToolDoesNotGrantAccess() {
        Fixture fixture = setUpAgentToolAndServer();
        consentService.create(new CreateConsentRequest(fixture.agent().getId(), fixture.server().getId(),
                "some-other-tool", null, null), "security-analyst-1");

        var response = invokeEcho(fixture);

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.reason()).contains("no active MCP consent");
    }

    @Test
    void revokedConsentDeniesTheNextCallEvenThoughAnEarlierCallSucceeded() {
        Fixture fixture = setUpAgentToolAndServer();
        McpConsent consent = consentService.create(new CreateConsentRequest(fixture.agent().getId(),
                fixture.server().getId(), null, null, null), "security-analyst-1");

        assertThat(invokeEcho(fixture).decision()).isEqualTo(PolicyDecisionType.ALLOW);

        consentService.revoke(consent.getId(), "security-analyst-1");

        var response = invokeEcho(fixture);
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.reason()).contains("no active MCP consent");
    }

    @Test
    void twoAgentsWithSeparateConsentsToTheSameServerDoNotAffectEachOther() {
        Fixture fixtureOne = setUpAgentToolAndServer();
        // Reuse the same MCP server for a second agent so both agents call the same server.
        Fixture fixtureTwo = setUpAgentToolAndServerOnExistingServer(fixtureOne.server());

        McpConsent consentOne = consentService.create(new CreateConsentRequest(fixtureOne.agent().getId(),
                fixtureOne.server().getId(), null, null, null), "security-analyst-1");
        consentService.create(new CreateConsentRequest(fixtureTwo.agent().getId(), fixtureTwo.server().getId(),
                null, null, null), "security-analyst-1");

        consentService.revoke(consentOne.getId(), "security-analyst-1");

        assertThat(invokeEcho(fixtureOne).decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(invokeEcho(fixtureTwo).decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    private Fixture setUpAgentToolAndServerOnExistingServer(McpServer server) {
        Tool echoTool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();

        String plaintextToken = "mcp-test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("mcp-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("mcp");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        return new Fixture(agent, plaintextToken, echoTool, server);
    }

    @Test
    void gatewayInvokeAttachesAValidOauthTokenToAnOauthProtectedMcpServer() {
        Fixture fixture = setUpAgentToolAndServer();
        String issuer = "http://localhost:" + port + "/demo/mock-oauth-server";
        MockOAuthServerController.issuerOverride.set(issuer);
        McpServer server = discoveryService.updateAuth(fixture.server().getId(), new UpdateMcpAuthRequest(
                McpAuthMode.OAUTH2, issuer, fixture.server().getEndpointUrl(), null, "test-client", null, null));
        consentService.create(new CreateConsentRequest(fixture.agent().getId(), server.getId(), null, null, null),
                "security-analyst-1");

        // Prime and capture the exact token AgentShield will use, so the mock MCP server can
        // verify it received precisely that token (proving attachment, not just "some" header).
        var tokenResult = oauthTokenService.getValidToken(server);
        assertThat(tokenResult.success()).isTrue();
        MockMcpServerController.requiredBearerToken.set(tokenResult.accessToken());

        var response = invokeEcho(fixture);

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.result().get("toolName").asText()).isEqualTo("echo");
    }
}
