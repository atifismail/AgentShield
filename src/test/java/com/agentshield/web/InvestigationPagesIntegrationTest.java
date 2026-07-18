package com.agentshield.web;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.TokenHasher;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.agentshield.tool.ToolVersion;
import com.agentshield.tool.ToolVersionRepository;
import com.agentshield.tool.ToolVersionStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * Covers the investigation detail pages added for improvement_plan.md #11 — the acceptance
 * criterion is "a security analyst can investigate a blocked action from dashboard to audit
 * timeline in under three clicks," so these pages must render (200 OK) and surface the data an
 * analyst needs, not just exist as routes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class InvestigationPagesIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private ToolVersionRepository toolVersionRepository;
    @Autowired
    private GatewayRequestRepository gatewayRequestRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    @Test
    void agentDetailPageShowsCredentialsAndRecentCalls() {
        String plaintextToken = "test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("it-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("database");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        var response = admin.getForEntity("http://localhost:" + port + "/agents/" + agent.getId(), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains(credential.getTokenPrefix());
    }

    @Test
    void gatewayRequestDetailPageShowsPolicyDecisionAndResponseScan() {
        String plaintextToken = "test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("it-agent-" + System.nanoTime());
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
        tool.setName("it-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup("database");
        tool.setEndpointUrl("http://localhost:" + port + "/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setApprovedHash("h");
        tool.setCurrentHash("h");
        tool = toolRepository.save(tool);

        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "doSomething");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("key", "value"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);
        TestRestTemplate anon = new TestRestTemplate();
        anon.postForEntity("http://localhost:" + port + "/api/gateway/invoke", new HttpEntity<>(body, headers), String.class);

        GatewayRequest gatewayRequest = gatewayRequestRepository
                .findByAgentIdOrderByCreatedAtDesc(agent.getId(), org.springframework.data.domain.PageRequest.of(0, 1))
                .getContent().get(0);

        var response = admin.getForEntity("http://localhost:" + port + "/gateway-requests/" + gatewayRequest.getId(), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Policy decision");
        assertThat(response.getBody()).contains("Response scan result");
    }

    @Test
    void toolDetailPageShowsDriftDiffWhenDrifted() {
        Tool tool = new Tool();
        tool.setName("it-tool-drifted-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup("database");
        tool.setEndpointUrl("/demo/tools/database");
        tool.setApprovalStatus(ToolApprovalStatus.DRIFTED);
        tool.setApprovedHash("approved-hash");
        tool.setCurrentHash("current-hash");
        tool = toolRepository.save(tool);

        ToolVersion approved = new ToolVersion();
        approved.setTool(tool);
        approved.setHash("approved-hash");
        approved.setDescription("original description");
        approved.setSchemaJson("{\"fields\":[\"a\",\"b\"]}");
        approved.setStatus(ToolVersionStatus.APPROVED);
        toolVersionRepository.save(approved);

        ToolVersion current = new ToolVersion();
        current.setTool(tool);
        current.setHash("current-hash");
        current.setDescription("changed description");
        current.setSchemaJson("{\"fields\":[\"a\",\"b\",\"c\"]}");
        current.setStatus(ToolVersionStatus.DETECTED);
        toolVersionRepository.save(current);

        var response = admin.getForEntity("http://localhost:" + port + "/tools/" + tool.getId(), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Drift diff");
        assertThat(response.getBody()).contains("changed description");
    }
}
