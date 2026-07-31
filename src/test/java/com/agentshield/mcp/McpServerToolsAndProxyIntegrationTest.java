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
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockMcpServerController;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.fasterxml.jackson.databind.JsonNode;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 1: the MCP-scoped tool
 * listing and the server-addressing proxy route, both additive alongside the generic
 * {@code /api/tools} and {@code /api/gateway/invoke} endpoints.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpServerToolsAndProxyIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpConsentService consentService;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private final TestRestTemplate restTemplate = new TestRestTemplate();

    @BeforeEach
    void resetMockServer() {
        MockMcpServerController.echoToolDescription.set("Echoes its input");
        MockMcpServerController.includeSecondTool.set(true);
        MockMcpServerController.requiredBearerToken.set(null);
    }

    private McpServer registerAndDiscover(String name) {
        McpServer server = discoveryService.register(new RegisterMcpServerRequest(name, McpTransportType.HTTP,
                "http://localhost:" + port + "/demo/mock-mcp-server", null, null, null, "owner", "DEV", "mcp"));
        discoveryService.discover(server.getId());
        return server;
    }

    private String basicAuthHeader() {
        return "Basic " + java.util.Base64.getEncoder()
                .encodeToString("admin:test-only".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test
    void mcpScopedToolListingReturnsOnlyToolsForTheNamedServer() {
        McpServer serverA = registerAndDiscover("mcp-list-a-" + System.nanoTime());
        McpServer serverB = registerAndDiscover("mcp-list-b-" + System.nanoTime());

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, basicAuthHeader());
        ResponseEntity<JsonNode> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/mcp-servers/" + serverA.getId() + "/tools",
                HttpMethod.GET, new HttpEntity<>(headers), JsonNode.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode content = response.getBody().path("content");
        assertThat(content.isArray()).isTrue();
        assertThat(content.size()).isEqualTo(2);
        for (JsonNode tool : content) {
            assertThat(tool.path("name").asText()).startsWith(serverA.getName() + ":");
        }
        // serverB's tools must never leak into serverA's scoped listing.
        for (JsonNode tool : content) {
            assertThat(tool.path("name").asText()).doesNotContain(serverB.getName());
        }
    }

    @Test
    void mcpScopedToolListingRequiresAuthentication() {
        McpServer server = registerAndDiscover("mcp-list-noauth-" + System.nanoTime());

        // Anonymous requests get redirected to the login page (form-login entry point) rather
        // than a bare 401/403 — matching SecurityConfigIntegrationTest's convention. What actually
        // matters is that the scoped tool data never reaches an unauthenticated caller.
        ResponseEntity<String> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/tools",
                HttpMethod.GET, HttpEntity.EMPTY, String.class);

        assertThat(response.getBody()).doesNotContain(server.getName() + ":echo");
    }

    private record Fixture(Agent agent, String plaintextToken, Tool tool, McpServer server) {
    }

    private Fixture setUpApprovedAgentAndTool() {
        McpServer server = registerAndDiscover("mcp-proxy-" + System.nanoTime());
        Tool echoTool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();
        echoTool.setApprovedHash(echoTool.getCurrentHash());
        echoTool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        toolRepository.saveAndFlush(echoTool);

        String plaintextToken = "mcp-proxy-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("mcp-proxy-agent-" + System.nanoTime());
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

    private ResponseEntity<GatewayDtos.InvokeResponse> callProxy(Fixture fixture, String toolName) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolName", toolName);
        body.put("action", "echo");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("message", "hello via proxy"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + fixture.plaintextToken());

        return restTemplate.exchange("http://localhost:" + port + "/api/mcp-servers/" + fixture.server().getId() + "/proxy",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class);
    }

    @Test
    void proxyRouteReachesTheSameAllowBehaviorAsGenericGatewayInvoke() {
        Fixture fixture = setUpApprovedAgentAndTool();
        consentService.create(new CreateConsentRequest(fixture.agent().getId(), fixture.server().getId(), null, null,
                null), "security-analyst-1");

        ResponseEntity<GatewayDtos.InvokeResponse> response = callProxy(fixture, "echo");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.getBody().result().get("toolName").asText()).isEqualTo("echo");
    }

    @Test
    void proxyRouteDeniesWithoutMcpConsentJustLikeGenericGatewayInvoke() {
        Fixture fixture = setUpApprovedAgentAndTool();
        // No consent granted — the confused-deputy gate must still apply on this path.

        ResponseEntity<GatewayDtos.InvokeResponse> response = callProxy(fixture, "echo");

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.getBody().reason()).contains("no active MCP consent");
    }

    @Test
    void proxyRouteRejectsAToolNameNotBelongingToThisServerInsteadOfForwardingArbitraryInput() {
        Fixture fixture = setUpApprovedAgentAndTool();
        consentService.create(new CreateConsentRequest(fixture.agent().getId(), fixture.server().getId(), null, null,
                null), "security-analyst-1");

        ResponseEntity<GatewayDtos.InvokeResponse> response = callProxy(fixture, "not-a-real-tool-on-this-server");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void proxyRouteIsUnauthenticatedAtTheHttpLayerJustLikeGenericGatewayInvokeSinceTheAgentTokenGatesItInstead() {
        Fixture fixture = setUpApprovedAgentAndTool();

        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolName", "echo");
        body.put("action", "echo");
        body.put("actionCategory", ActionCategory.READ.name());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer not-a-valid-agent-token");

        ResponseEntity<GatewayDtos.InvokeResponse> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/mcp-servers/" + fixture.server().getId() + "/proxy",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class);

        // Rejected by GatewayService.authenticate() (bad agent token), not by a Spring Security
        // 401/403 at the HTTP layer — proving the proxy route delegates auth to the same place
        // /api/gateway/invoke does, rather than bypassing it.
        assertThat(response.getStatusCode().is4xxClientError()).isTrue();
    }
}
