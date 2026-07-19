package com.agentshield.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.audit.AuditEventRepository;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.TokenHasher;
import com.agentshield.gateway.GatewayDtos.InvokeResponse;
import com.agentshield.mcp.McpConsentDtos.CreateConsentRequest;
import com.agentshield.mcp.McpConsentService;
import com.agentshield.mcp.McpDiscoveryService;
import com.agentshield.mcp.McpServer;
import com.agentshield.mcp.McpTransportType;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockMcpServerController;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolProvenanceRepository;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolService;
import com.agentshield.tool.ToolType;
import com.agentshield.tool.ToolVersion;
import com.agentshield.tool.ToolVersionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * End-to-end "does the product hold together?" smoke scenario:
 * agent credential -> MCP discovery -> tool approval -> MCP consent -> gateway invoke -> audit/provenance.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ProductionReadinessScenarioTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService mcpDiscoveryService;
    @Autowired
    private McpConsentService mcpConsentService;
    @Autowired
    private ToolService toolService;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private ToolVersionRepository toolVersionRepository;
    @Autowired
    private ToolProvenanceRepository toolProvenanceRepository;
    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private AuditEventRepository auditEventRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private String plaintextToken;

    @BeforeEach
    void resetMockServer() {
        MockMcpServerController.echoToolDescription.set("Echoes its input");
        MockMcpServerController.includeSecondTool.set(true);
        MockMcpServerController.requiredBearerToken.set(null);
    }

    @Test
    void mcpToolCanBeApprovedConsentedAndInvokedEndToEnd() {
        McpServer server = mcpDiscoveryService.register(new com.agentshield.mcp.McpDtos.RegisterMcpServerRequest(
                "prod-scenario-mcp-" + System.nanoTime(), McpTransportType.HTTP,
                "http://localhost:" + port + "/demo/mock-mcp-server", null, null, null,
                "security-team", "DEV", "mcp"));
        mcpDiscoveryService.discover(server.getId());

        Tool tool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();
        ToolVersion latest = toolVersionRepository.findByToolIdOrderByDetectedAtDesc(tool.getId()).get(0);
        assertThat(toolProvenanceRepository.findByToolVersionId(latest.getId())).isPresent();

        toolService.approveLatestVersion(tool.getId(), "security-analyst-1");

        plaintextToken = "scenario-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("scenario-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("mcp");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        mcpConsentService.create(new CreateConsentRequest(agent.getId(), server.getId(), null, null, null),
                "security-analyst-1");

        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "echo");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("message", "production-readiness"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);

        InvokeResponse response = new TestRestTemplate().exchange(
                "http://localhost:" + port + "/api/gateway/invoke",
                org.springframework.http.HttpMethod.POST,
                new HttpEntity<>(body, headers),
                InvokeResponse.class).getBody();

        assertThat(response).isNotNull();
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.result()).isNotNull();
        assertThat(response.result().get("echoedArguments").get("message").asText()).isEqualTo("production-readiness");
        assertThat(auditEventRepository.count()).isGreaterThan(0);
    }
}
