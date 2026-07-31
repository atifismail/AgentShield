package com.agentshield.grant;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.grant.GrantDtos.CreateGrantRequest;
import com.agentshield.grant.GrantDtos.GrantResponse;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 2, "Only ADMIN can
 * create/revoke... every mutation writes an audit event" plus the "API role tests" required test.
 * Follows this codebase's existing role-test convention (e.g. SecurityConfigIntegrationTest,
 * IncidentStatusApiIntegrationTest): ADMIN-succeeds vs. anonymous-rejected, rather than seeding a
 * dedicated non-admin test user account (no existing test does the latter either).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AgentToolGrantApiSecurityTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private ToolRepository toolRepository;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    private Agent seedAgent() {
        Agent agent = new Agent();
        agent.setName("grant-api-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        return agentRepository.save(agent);
    }

    private Tool seedTool() {
        Tool tool = new Tool();
        tool.setName("grant-api-test-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        return toolRepository.save(tool);
    }

    @Test
    void adminCanCreateListAndRevokeAGrant() {
        Agent agent = seedAgent();
        Tool tool = seedTool();
        String base = "http://localhost:" + port + "/api/agents/" + agent.getId() + "/grants";

        var createRequest = new CreateGrantRequest(tool.getId(), null, "DEV", null, null, null, null, "test grant");
        ResponseEntity<GrantResponse> createResponse = admin.postForEntity(base, createRequest, GrantResponse.class);
        assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Long grantId = createResponse.getBody().id();
        assertThat(createResponse.getBody().status()).isEqualTo(GrantStatus.ACTIVE);

        ResponseEntity<GrantResponse[]> listResponse = admin.getForEntity(base, GrantResponse[].class);
        assertThat(listResponse.getBody()).extracting(GrantResponse::id).contains(grantId);

        ResponseEntity<GrantResponse> revokeResponse = admin.postForEntity(base + "/" + grantId + "/revoke",
                Map.of("reason", "no longer needed"), GrantResponse.class);
        assertThat(revokeResponse.getBody().status()).isEqualTo(GrantStatus.REVOKED);
    }

    @Test
    void anonymousCannotCreateAGrant() {
        Agent agent = seedAgent();
        Tool tool = seedTool();
        TestRestTemplate anon = new TestRestTemplate();

        var createRequest = new CreateGrantRequest(tool.getId(), null, "DEV", null, null, null, null, null);
        ResponseEntity<String> response = anon.postForEntity(
                "http://localhost:" + port + "/api/agents/" + agent.getId() + "/grants", createRequest, String.class);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.CREATED);
    }

    @Test
    void anonymousListingGrantsNeverLeaksGrantData() {
        Agent agent = seedAgent();
        Tool tool = seedTool();
        admin.postForEntity("http://localhost:" + port + "/api/agents/" + agent.getId() + "/grants",
                new CreateGrantRequest(tool.getId(), null, "DEV", null, null, null, null, "secret-ish reason"),
                GrantResponse.class);

        TestRestTemplate anon = new TestRestTemplate();
        ResponseEntity<String> response = anon.exchange(
                "http://localhost:" + port + "/api/agents/" + agent.getId() + "/grants",
                HttpMethod.GET, HttpEntity.EMPTY, String.class);

        assertThat(response.getBody()).doesNotContain("secret-ish reason");
    }

    @Test
    void creatingAGrantForAnUnknownToolReturns404() {
        Agent agent = seedAgent();
        var createRequest = new CreateGrantRequest(999_999_999L, null, "DEV", null, null, null, null, null);

        ResponseEntity<String> response = admin.postForEntity(
                "http://localhost:" + port + "/api/agents/" + agent.getId() + "/grants", createRequest, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
