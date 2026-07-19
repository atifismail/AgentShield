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
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.policy.PolicyDtos.ReplayResponse;
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
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * improvement_plan.md P3 "Add Policy Simulation And Replay Lab": an operator can pick a historical
 * gateway request and see what the live policy engine (including current overrides) would decide
 * today, without ever calling the downstream tool.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PolicyReplayIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private GatewayRequestRepository gatewayRequestRepository;
    @Autowired
    private PolicyOverrideService overrideService;
    @Autowired
    private ObjectMapper objectMapper;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    @Test
    void replayShowsUnchangedDecisionThenDivergesAfterAnOverride() {
        String plaintextToken = "replay-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("replay-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("database");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        Tool tool = new Tool();
        tool.setName("replay-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup("database");
        tool.setEndpointUrl("http://localhost:" + port + "/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setApprovedHash("h");
        tool.setCurrentHash("h");
        tool = toolRepository.save(tool);

        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "lookupRecords");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);
        var invokeResponse = new TestRestTemplate().exchange("http://localhost:" + port + "/api/gateway/invoke",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class);
        assertThat(invokeResponse.getBody().decision()).isEqualTo(PolicyDecisionType.ALLOW);

        GatewayRequest gatewayRequest = gatewayRequestRepository
                .findByAgentIdOrderByCreatedAtDesc(agent.getId(), PageRequest.of(0, 1)).getContent().get(0);

        var firstReplay = admin.getForEntity(
                "http://localhost:" + port + "/api/policies/replay/" + gatewayRequest.getId(), ReplayResponse.class);
        assertThat(firstReplay.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(firstReplay.getBody().originalDecision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(firstReplay.getBody().simulatedDecision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(firstReplay.getBody().decisionChanged()).isFalse();

        overrideService.create(new CreateOverrideRequest(ActionCategory.READ, "DEV", "database", agent.getName(),
                PolicyDecisionType.DENY, "replay-lab-test freeze", null), "security-analyst");

        var secondReplay = admin.getForEntity(
                "http://localhost:" + port + "/api/policies/replay/" + gatewayRequest.getId(), ReplayResponse.class);
        assertThat(secondReplay.getBody().originalDecision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(secondReplay.getBody().simulatedDecision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(secondReplay.getBody().decisionChanged()).isTrue();
        assertThat(secondReplay.getBody().simulatedReason()).contains("replay-lab-test freeze");

        // The tool must never be re-invoked by a replay — the agent's allowed-groups/etc. facts
        // came only from the stored request, not a fresh call, so there's nothing to assert on
        // the tool side beyond: the original decision is untouched by the override added after it.
        var reReadOriginal = admin.getForEntity(
                "http://localhost:" + port + "/api/policies/replay/" + gatewayRequest.getId(), ReplayResponse.class);
        assertThat(reReadOriginal.getBody().originalDecision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void replayingARequestWithNoResolvedToolIsRejected() {
        String plaintextToken = "replay-token-notool-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("replay-agent-notool-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("database");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", "does-not-exist-" + System.nanoTime());
        body.put("action", "lookupRecords");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);
        new TestRestTemplate().exchange("http://localhost:" + port + "/api/gateway/invoke", HttpMethod.POST,
                new HttpEntity<>(body, headers), String.class);

        GatewayRequest gatewayRequest = gatewayRequestRepository
                .findByAgentIdOrderByCreatedAtDesc(agent.getId(), PageRequest.of(0, 1)).getContent().get(0);
        assertThat(gatewayRequest.getTool()).isNull();

        var response = admin.getForEntity(
                "http://localhost:" + port + "/api/policies/replay/" + gatewayRequest.getId(), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
