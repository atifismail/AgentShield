package com.agentshield.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.approval.ApprovalRequest;
import com.agentshield.approval.ApprovalRequestRepository;
import com.agentshield.approval.ApprovalService;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.ApprovalStatus;
import com.agentshield.common.GatewayRequestStatus;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.TokenHasher;
import com.agentshield.incident.IncidentRepository;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewayServiceIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private GatewayRequestRepository gatewayRequestRepository;
    @Autowired
    private ApprovalRequestRepository approvalRequestRepository;
    @Autowired
    private IncidentRepository incidentRepository;
    @Autowired
    private ApprovalService approvalService;
    @Autowired
    private ObjectMapper objectMapper;

    private final TestRestTemplate rest = new TestRestTemplate();
    private String plaintextToken;

    @BeforeEach
    void resetToken() {
        plaintextToken = null;
    }

    private Agent createAgent(AgentStatus status, String... groups) {
        plaintextToken = "test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("it-agent-" + System.nanoTime());
        agent.setStatus(status);
        agent.setApiKeyHash(TokenHasher.sha256Hex(plaintextToken));
        agent.setAllowedToolGroups(String.join(",", groups));
        return agentRepository.save(agent);
    }

    private Tool createTool(ToolApprovalStatus status, String group, String endpointPath) {
        Tool tool = new Tool();
        tool.setName("it-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup(group);
        tool.setEndpointUrl("http://localhost:" + port + endpointPath);
        tool.setApprovalStatus(status);
        tool.setApprovedHash(status == ToolApprovalStatus.APPROVED ? "h" : null);
        tool.setCurrentHash(status == ToolApprovalStatus.DRIFTED ? "different-hash" : "h");
        return toolRepository.save(tool);
    }

    private ResponseEntity<GatewayDtos.InvokeResponse> invoke(Tool tool, ActionCategory category, String env) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "doSomething");
        body.put("actionCategory", category.name());
        body.put("targetEnvironment", env);
        body.set("input", objectMapper.createObjectNode().put("key", "value"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);

        return rest.exchange("http://localhost:" + port + "/api/gateway/invoke", org.springframework.http.HttpMethod.POST,
                new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class);
    }

    @Test
    void allowedCallForwardsToToolAndReturnsResult() {
        createAgent(AgentStatus.ENABLED, "database");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "database", "/demo/mock-tool/echo");

        var response = invoke(tool, ActionCategory.READ, "DEV");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.getBody().result().get("key").asText()).isEqualTo("value");
    }

    @Test
    void relativeEndpointUrlIsResolvedAgainstThisServer() {
        // Matches how the real demo seed data registers tools (db/migration/*/V2__seed_demo_data.sql):
        // a bare path like "/demo/tools/git" with no scheme/host, since the tool lives in this app.
        createAgent(AgentStatus.ENABLED, "database");
        Tool tool = new Tool();
        tool.setName("it-tool-relative-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup("database");
        tool.setEndpointUrl("/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setApprovedHash("h");
        tool.setCurrentHash("h");
        tool = toolRepository.save(tool);

        var response = invoke(tool, ActionCategory.READ, "DEV");

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.getBody().result().get("key").asText()).isEqualTo("value");
    }

    @Test
    void deniedCallNeverReachesTool() {
        createAgent(AgentStatus.DISABLED, "database");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "database", "/demo/mock-tool/fail");

        var response = invoke(tool, ActionCategory.READ, "DEV");

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.getBody().reason()).contains("disabled");
    }

    @Test
    void unregisteredToolIsDenied() {
        createAgent(AgentStatus.ENABLED, "database");
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", "does-not-exist");
        body.put("action", "doSomething");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);

        var response = rest.exchange("http://localhost:" + port + "/api/gateway/invoke",
                org.springframework.http.HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class);

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.getBody().reason()).contains("not registered");
    }

    @Test
    void driftedToolIsDenied() {
        createAgent(AgentStatus.ENABLED, "database");
        Tool tool = createTool(ToolApprovalStatus.DRIFTED, "database", "/demo/mock-tool/echo");

        var response = invoke(tool, ActionCategory.READ, "DEV");

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.getBody().reason()).contains("drift");
    }

    @Test
    void toolOutsideAllowedGroupIsDenied() {
        createAgent(AgentStatus.ENABLED, "filesystem");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "database", "/demo/mock-tool/echo");

        var response = invoke(tool, ActionCategory.READ, "DEV");

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.getBody().reason()).contains("not allowed to call tool group");
    }

    @Test
    void invalidTokenIsUnauthorized() {
        createAgent(AgentStatus.ENABLED, "database");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "database", "/demo/mock-tool/echo");
        plaintextToken = "not-a-real-token";

        var response = invoke(tool, ActionCategory.READ, "DEV");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void prodWriteRequiresApprovalAndApprovingExecutesIt() {
        createAgent(AgentStatus.ENABLED, "database");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "database", "/demo/mock-tool/echo");

        var response = invoke(tool, ActionCategory.WRITE, "PROD");
        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.APPROVAL_REQUIRED);
        Long approvalId = response.getBody().approvalRequestId();
        assertThat(approvalId).isNotNull();

        ApprovalRequest approval = approvalRequestRepository.findById(approvalId).orElseThrow();
        assertThat(approval.getStatus()).isEqualTo(ApprovalStatus.PENDING);

        var executed = approvalService.approve(approvalId, "security-analyst-1");
        assertThat(executed.status()).isEqualTo(ApprovalStatus.APPROVED);
        assertThat(executed.executionResult().decision()).isEqualTo(PolicyDecisionType.ALLOW);

        GatewayRequest gatewayRequest = gatewayRequestRepository.findById(approval.getGatewayRequest().getId()).orElseThrow();
        assertThat(gatewayRequest.getStatus()).isEqualTo(GatewayRequestStatus.COMPLETED);
    }

    @Test
    void rejectingApprovalKeepsRequestDenied() {
        createAgent(AgentStatus.ENABLED, "database");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "database", "/demo/mock-tool/echo");

        var response = invoke(tool, ActionCategory.WRITE, "PROD");
        Long approvalId = response.getBody().approvalRequestId();

        var rejected = approvalService.reject(approvalId, "security-analyst-1");
        assertThat(rejected.status()).isEqualTo(ApprovalStatus.REJECTED);

        ApprovalRequest approval = approvalRequestRepository.findById(approvalId).orElseThrow();
        assertThat(gatewayRequestRepository.findById(approval.getGatewayRequest().getId()).orElseThrow().getStatus())
                .isEqualTo(GatewayRequestStatus.DENIED);
    }

    @Test
    void secretInResponseIsBlockedForExternalTransferAndCreatesIncident() {
        createAgent(AgentStatus.ENABLED, "saas");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "saas", "/demo/mock-tool/secret");

        var response = invoke(tool, ActionCategory.EXTERNAL_TRANSFER, "DEV");
        Long approvalId = response.getBody().approvalRequestId();
        assertThat(approvalId).isNotNull();

        long incidentsBefore = incidentRepository.count();
        var executed = approvalService.approve(approvalId, "security-analyst-1");

        assertThat(executed.executionResult().decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(executed.executionResult().reason()).contains("secret-like value");
        assertThat(incidentRepository.count()).isEqualTo(incidentsBefore + 1);
    }

    @Test
    void promptInjectionInResponseIsBlockedAndCreatesIncident() {
        createAgent(AgentStatus.ENABLED, "database");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "database", "/demo/mock-tool/injection");

        long incidentsBefore = incidentRepository.count();
        var response = invoke(tool, ActionCategory.READ, "DEV");

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.getBody().reason()).contains("prompt-injection");
        assertThat(incidentRepository.count()).isEqualTo(incidentsBefore + 1);
    }

    @Test
    void toolCallFailureIsHandledGracefully() {
        createAgent(AgentStatus.ENABLED, "database");
        Tool tool = createTool(ToolApprovalStatus.APPROVED, "database", "/demo/mock-tool/fail");

        var response = invoke(tool, ActionCategory.READ, "DEV");

        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.getBody().reason()).contains("tool call failed");
    }
}
