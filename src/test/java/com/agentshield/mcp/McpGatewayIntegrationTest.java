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
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockMcpServerController;
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

/** Proves a discovered MCP tool flows through the exact same gateway/policy/audit pipeline as a plain HTTP tool. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpGatewayIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void resetMockServer() {
        MockMcpServerController.echoToolDescription.set("Echoes its input");
        MockMcpServerController.includeSecondTool.set(true);
    }

    @Test
    void gatewayInvokeThroughAnMcpToolWorksEndToEnd() {
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

        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", echoTool.getName());
        body.put("action", "echo");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("message", "hello via mcp"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);

        var response = new TestRestTemplate().exchange("http://localhost:" + port + "/api/gateway/invoke",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class);

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.getBody().result().get("toolName").asText()).isEqualTo("echo");
        assertThat(response.getBody().result().get("echoedArguments").get("message").asText())
                .isEqualTo("hello via mcp");
    }
}
