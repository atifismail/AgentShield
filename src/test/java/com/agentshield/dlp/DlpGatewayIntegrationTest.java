package com.agentshield.dlp;

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
import com.agentshield.dlp.DlpDtos.CreateProfileRequest;
import com.agentshield.gateway.GatewayDtos;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
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
 * Proves the inbound DLP scan wired into {@code GatewayService.doInvoke} (Phase 1, A2) actually
 * governs a real {@code /api/gateway/invoke} call, not just the unit-level {@code DlpScanService}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DlpGatewayIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private ClassificationProfileService profileService;
    @Autowired
    private ClassificationProfileRepository profileRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private String plaintextToken;
    private final List<Long> createdProfileIds = new ArrayList<>();

    /**
     * Classification profiles are global (unlike PolicyOverride, which can be scoped to a single
     * agent/tool). Any profile a test creates must be removed afterward, or it silently changes
     * DLP behavior for every other test in this shared, non-rolled-back database.
     */
    @AfterEach
    void cleanUpProfiles() {
        createdProfileIds.forEach(profileRepository::deleteById);
        createdProfileIds.clear();
    }

    private Agent createAgent(String... groups) {
        plaintextToken = "dlp-test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("dlp-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups(String.join(",", groups));
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);
        return agent;
    }

    private Tool createTool(String group) {
        Tool tool = new Tool();
        tool.setName("dlp-test-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup(group);
        tool.setEndpointUrl("/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setApprovedHash("h");
        tool.setCurrentHash("h");
        return toolRepository.save(tool);
    }

    private GatewayDtos.InvokeResponse invoke(Tool tool, com.fasterxml.jackson.databind.JsonNode input) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "doSomething");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", input);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);

        return new TestRestTemplate().exchange("http://localhost:" + port + "/api/gateway/invoke", HttpMethod.POST,
                new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
    }

    @Test
    void secretInInboundToolArgumentIsBlockedByBuiltInDefaultProfile() {
        // No ClassificationProfile configured -> DlpScanService falls back to its built-in
        // default (all detectors on, BLOCK on any match) -- fail-closed with zero setup required.
        Agent agent = createAgent("database");
        Tool tool = createTool("database");
        var input = objectMapper.createObjectNode().put("query", "access key: AKIAABCDEFGHIJKLMNOP");

        var response = invoke(tool, input);

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(response.reason()).contains("aws-access-key").contains("DLP");
        assertThat(response.reason()).doesNotContain("AKIAABCDEFGHIJKLMNOP");
    }

    @Test
    void ordinaryInboundArgumentIsUnaffectedByDlpScan() {
        Agent agent = createAgent("database");
        Tool tool = createTool("database");
        var input = objectMapper.createObjectNode().put("query", "select all active users");

        var response = invoke(tool, input);

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void redactProfileSanitizesInboundArgumentInsteadOfBlockingTheCall() {
        var profile = profileService.create(new CreateProfileRequest("test-redact-profile", null, true, true, true,
                null, DlpAction.REDACT, 1), "security-analyst");
        createdProfileIds.add(profile.getId());

        Agent agent = createAgent("database");
        Tool tool = createTool("database");
        var input = objectMapper.createObjectNode().put("query", "access key: AKIAABCDEFGHIJKLMNOP");

        var response = invoke(tool, input);

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(response.result().get("query").asText())
                .contains("[REDACTED:CREDENTIAL]")
                .doesNotContain("AKIAABCDEFGHIJKLMNOP");
    }
}
