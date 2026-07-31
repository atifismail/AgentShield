package com.agentshield.approval;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.approval.ApprovalProfileDtos.CreateApprovalProfileRequest;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.TokenHasher;
import com.agentshield.gateway.GatewayDtos;
import com.agentshield.security.UserRole;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.time.Instant;
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
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 3, end-to-end: "Expiration
 * comes from the selected profile" and "Profile disable/update ... never mutates a pending
 * request's assigned routing after creation."
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApprovalProfileGatewayIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private ApprovalProfileService approvalProfileService;
    @Autowired
    private ApprovalRequestRepository approvalRequestRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private final TestRestTemplate restTemplate = new TestRestTemplate();

    private Tool seedApprovedTool() {
        Tool tool = new Tool();
        tool.setName("profile-gw-tool-" + System.nanoTime());
        tool.setType(ToolType.SAAS);
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        String hash = TokenHasher.sha256Hex("x");
        tool.setApprovedHash(hash);
        tool.setCurrentHash(hash);
        return toolRepository.save(tool);
    }

    private String seedAgentAndToken(String toolGroup) {
        Agent agent = new Agent();
        agent.setName("profile-gw-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups(toolGroup);
        agent = agentRepository.save(agent);

        String plaintextToken = "profile-gw-token-" + System.nanoTime();
        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);
        return plaintextToken;
    }

    private GatewayDtos.InvokeResponse invokeExternalTransfer(Tool tool, String token) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "export");
        body.put("actionCategory", ActionCategory.EXTERNAL_TRANSFER.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        return restTemplate.exchange("http://localhost:" + port + "/api/gateway/invoke", HttpMethod.POST,
                new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
    }

    @Test
    void expirationAndRoleComeFromTheMatchedProfileInsteadOfTheDefault() {
        Tool tool = seedApprovedTool();
        String token = seedAgentAndToken(tool.getToolGroup());

        var profile = approvalProfileService.create(new CreateApprovalProfileRequest(
                "profile-gw-test-" + System.nanoTime(), null, 500, null, tool.getId(), null, null, null, null,
                UserRole.SECURITY_ANALYST, 5), "admin");

        var response = invokeExternalTransfer(tool, token);
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.APPROVAL_REQUIRED);

        ApprovalRequest stored = approvalRequestRepository.findById(response.approvalRequestId()).orElseThrow();
        assertThat(stored.getApprovalProfileId()).isEqualTo(profile.getId());
        assertThat(stored.getAssignedRole()).isEqualTo(UserRole.SECURITY_ANALYST);
        // Custom 5-minute expiration, not the 60-minute deployment default.
        assertThat(stored.getExpiresAt()).isBefore(Instant.now().plus(Duration.ofMinutes(6)));
        assertThat(stored.getExpiresAt()).isAfter(Instant.now().plus(Duration.ofMinutes(4)));
    }

    @Test
    void disablingAProfileAfterCreationNeverChangesAnAlreadyCreatedApprovalsRouting() {
        Tool tool = seedApprovedTool();
        String token = seedAgentAndToken(tool.getToolGroup());

        var profile = approvalProfileService.create(new CreateApprovalProfileRequest(
                "profile-gw-immutable-" + System.nanoTime(), null, 500, null, tool.getId(), null, null, null, null,
                UserRole.TOOL_OWNER, null), "admin");

        var firstResponse = invokeExternalTransfer(tool, token);
        Long firstApprovalId = firstResponse.approvalRequestId();

        approvalProfileService.setEnabled(profile.getId(), false, "admin");

        // The already-created approval's routing must be untouched by the later disable.
        ApprovalRequest afterDisable = approvalRequestRepository.findById(firstApprovalId).orElseThrow();
        assertThat(afterDisable.getApprovalProfileId()).isEqualTo(profile.getId());
        assertThat(afterDisable.getAssignedRole()).isEqualTo(UserRole.TOOL_OWNER);

        // A brand-new request now resolves with no matching profile (it's disabled).
        var secondResponse = invokeExternalTransfer(tool, token);
        ApprovalRequest second = approvalRequestRepository.findById(secondResponse.approvalRequestId()).orElseThrow();
        assertThat(second.getApprovalProfileId()).isNull();
        assertThat(second.getAssignedRole()).isNull();
    }

    @Test
    void noMatchingProfileLeavesTheNormalApprovalStateIntact() {
        Tool tool = seedApprovedTool();
        String token = seedAgentAndToken(tool.getToolGroup());

        var response = invokeExternalTransfer(tool, token);

        assertThat(response.decision()).isEqualTo(PolicyDecisionType.APPROVAL_REQUIRED);
        ApprovalRequest stored = approvalRequestRepository.findById(response.approvalRequestId()).orElseThrow();
        assertThat(stored.getApprovalProfileId()).isNull();
        assertThat(stored.getAssignedRole()).isNull();
        assertThat(stored.getStatus()).isEqualTo(com.agentshield.common.ApprovalStatus.PENDING);
    }
}
