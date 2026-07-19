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
import com.agentshield.mcp.McpDtos.McpTransportStatusResponse;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.security.AppUser;
import com.agentshield.security.AppUserRepository;
import com.agentshield.security.UserRole;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockSseMcpServerController;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Set;
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
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * design-stdio-sse-mcp-transport-and-sandboxing.md §9/§12. SSE is HTTP-based, so this is much
 * lighter than the stdio suite — no subprocess/environment/filesystem concerns, just the
 * persistent-connection handshake, response correlation, timeout, and output-size limit.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        // Several tests intentionally leave a broken/unresponsive SSE connection open (a real
        // long-lived Tomcat async request) to exercise the negative paths — without capping this,
        // Spring's default 30s graceful-shutdown wait pointlessly delays every test run waiting
        // for those deliberately-never-closing requests to finish on their own.
        "spring.lifecycle.timeout-per-shutdown-phase=2s",
        "agentshield.mcp.sse.call-timeout-seconds=3",
        "agentshield.mcp.sse.max-response-bytes=8192",
        "agentshield.mcp.sse.reconnect-max-attempts=1"
})
class McpSseIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpConsentService consentService;
    @Autowired
    private McpToolInvoker toolInvoker;
    @Autowired
    private McpSseConnectionManager sseConnectionManager;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private AppUserRepository appUserRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    @BeforeEach
    void resetMockServer() {
        MockSseMcpServerController.reset();
    }

    private TestRestTemplate securityAnalystClient() {
        String username = "sse-security-analyst-" + System.nanoTime();
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode("test-only"));
        user.setEnabled(true);
        user.setRoles(Set.of(UserRole.SECURITY_ANALYST));
        appUserRepository.save(user);
        return new TestRestTemplate(username, "test-only");
    }

    private McpServer registerSseServer() {
        return discoveryService.register(new RegisterMcpServerRequest("sse-test-" + System.nanoTime(),
                McpTransportType.SSE, "http://localhost:" + port + "/demo/mock-sse-mcp-server", null, null, null,
                "owner", "DEV", "mcp"));
    }

    private record Fixture(Agent agent, String plaintextToken) {
    }

    private Fixture createAgentWithCredential(String toolGroup) {
        String plaintextToken = "sse-test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("sse-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups(toolGroup);
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);
        return new Fixture(agent, plaintextToken);
    }

    private GatewayDtos.InvokeResponse invoke(Fixture fixture, Tool tool) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "echo");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("message", "hi"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + fixture.plaintextToken());
        return new TestRestTemplate().exchange("http://localhost:" + port + "/api/gateway/invoke",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
    }

    private Tool approvedEchoTool(McpServer server) {
        discoveryService.discover(server.getId());
        Tool tool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();
        tool.setApprovedHash(tool.getCurrentHash());
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        toolRepository.saveAndFlush(tool);
        return tool;
    }

    @Test
    void happyPathDiscoversAndInvokesAnEchoToolThroughTheGateway() {
        McpServer server = registerSseServer();
        Tool tool = approvedEchoTool(server);

        Fixture fixture = createAgentWithCredential("mcp");
        consentService.create(new CreateConsentRequest(fixture.agent().getId(), server.getId(), null, null, null),
                "security-analyst-1");

        var response = invoke(fixture, tool);
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.result().get("echoedArguments").get("message").asText()).isEqualTo("hi");
    }

    @Test
    void missingEndpointEventFailsConnectClosed() {
        MockSseMcpServerController.neverSendEndpointEvent.set(true);
        McpServer server = registerSseServer();

        var result = toolInvoker.invoke(server.getId(), "echo", objectMapper.createObjectNode());
        assertThat(result.success()).isFalse();
    }

    @Test
    void droppedConnectionFailsConnectClosed() {
        MockSseMcpServerController.dropConnectionOnConnect.set(true);
        McpServer server = registerSseServer();

        var result = toolInvoker.invoke(server.getId(), "echo", objectMapper.createObjectNode());
        assertThat(result.success()).isFalse();
    }

    @Test
    void oversizedResponseFailsClosed() {
        McpServer server = registerSseServer();
        MockSseMcpServerController.sendOversizedResponse.set(true);

        var result = toolInvoker.invoke(server.getId(), "echo", objectMapper.createObjectNode());
        assertThat(result.success()).isFalse();
    }

    @Test
    void callTimeoutFailsClosed() {
        McpServer server = registerSseServer();
        MockSseMcpServerController.neverRespond.set(true);

        var result = toolInvoker.invoke(server.getId(), "echo", objectMapper.createObjectNode());
        assertThat(result.success()).isFalse();
        assertThat(result.errorMessage()).containsIgnoringCase("timed out");
    }

    @Test
    void manualStartStatusAndStopWorkViaTheAdminApi() {
        McpServer server = registerSseServer();

        var startResponse = admin.postForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/sse/start", null,
                McpTransportStatusResponse.class);
        assertThat(startResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(startResponse.getBody().running()).isTrue();

        var statusResponse = securityAnalystClient().getForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/sse/status",
                McpTransportStatusResponse.class);
        assertThat(statusResponse.getBody().running()).isTrue();

        var stopResponse = admin.postForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/sse/stop", null,
                McpTransportStatusResponse.class);
        assertThat(stopResponse.getBody().running()).isFalse();
    }

    @Test
    void nonAdminCannotStartOrStopAnSseConnection() {
        McpServer server = registerSseServer();
        TestRestTemplate securityAnalyst = securityAnalystClient();

        var startAttempt = securityAnalyst.postForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/sse/start", null, String.class);
        assertThat(startAttempt.getStatusCode()).isNotEqualTo(HttpStatus.OK);
    }

    @Test
    void consentStillGatesAnSseBackedToolInvocation() {
        McpServer server = registerSseServer();
        Tool tool = approvedEchoTool(server);

        Fixture fixture = createAgentWithCredential("mcp");
        // Deliberately no McpConsent grant.

        var response = invoke(fixture, tool);
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
    }
}
