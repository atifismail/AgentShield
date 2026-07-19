package com.agentshield.governance;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.TokenHasher;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
 * improvement_plan.md P2 "AI RMF Governance Mapping": an operator can export a governance
 * evidence report for a date range, in both JSON and Markdown, and only Admin/Security Analyst
 * roles may do so.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GovernanceReportIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    @Test
    void reportCapturesDeniedActionsApprovalsAndToolsInRange() {
        Instant from = Instant.now().minus(1, ChronoUnit.MINUTES);

        String plaintextToken = "gov-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("gov-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("filesystem");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        Tool tool = new Tool();
        tool.setName("gov-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup("database");
        tool.setEndpointUrl("http://localhost:" + port + "/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setApprovedHash("h");
        tool.setCurrentHash("h");
        tool = toolRepository.save(tool);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);
        TestRestTemplate anon = new TestRestTemplate();

        // Denied: agent is only allowed "filesystem", tool is "database" group.
        ObjectNode deniedBody = objectMapper.createObjectNode();
        deniedBody.put("toolId", tool.getName());
        deniedBody.put("action", "lookupRecords");
        deniedBody.put("actionCategory", ActionCategory.READ.name());
        deniedBody.put("targetEnvironment", "DEV");
        anon.postForEntity("http://localhost:" + port + "/api/gateway/invoke", new HttpEntity<>(deniedBody, headers), String.class);

        Instant to = Instant.now().plus(1, ChronoUnit.MINUTES);

        var jsonResponse = admin.getForEntity("http://localhost:" + port + "/api/governance/report?from=" + from + "&to=" + to,
                String.class);
        assertThat(jsonResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(jsonResponse.getBody()).contains(agent.getName());
        assertThat(jsonResponse.getBody()).contains(tool.getName());
        assertThat(jsonResponse.getBody()).contains("not allowed to call tool group");

        var markdownResponse = admin.getForEntity(
                "http://localhost:" + port + "/api/governance/report?format=markdown&from=" + from + "&to=" + to, String.class);
        assertThat(markdownResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(markdownResponse.getHeaders().getContentType().toString()).contains("text/markdown");
        assertThat(markdownResponse.getBody()).contains("# AgentShield Governance Evidence Report");
        assertThat(markdownResponse.getBody()).contains(agent.getName());
    }

    @Test
    void invalidRangeIsRejected() {
        Instant now = Instant.now();
        var response = admin.getForEntity(
                "http://localhost:" + port + "/api/governance/report?from=" + now + "&to=" + now.minusSeconds(60), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void anonymousCannotExportGovernanceReport() {
        // Anonymous requests to a protected endpoint hit the form-login entry point, which
        // redirects rather than returning a bare 401/403 (same behavior as every other RBAC-gated
        // API in this app) — so what's actually asserted is that no report data is returned, not
        // a specific status code. TestRestTemplate follows the redirect by default, landing on
        // the login page (200 OK) rather than the JSON report.
        TestRestTemplate anon = new TestRestTemplate();
        Instant now = Instant.now();
        var response = anon.getForEntity(
                "http://localhost:" + port + "/api/governance/report?from=" + now.minusSeconds(60) + "&to=" + now, String.class);

        assertThat(response.getBody()).doesNotContain("registeredAgents");
    }
}
