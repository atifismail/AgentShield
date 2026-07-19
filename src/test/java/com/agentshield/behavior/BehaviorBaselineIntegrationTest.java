package com.agentshield.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.audit.AuditEventRepository;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.TokenHasher;
import com.agentshield.incident.Incident;
import com.agentshield.incident.IncidentRepository;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * improvement_plan.md P2 "Agent Behavior Baselines And Anomaly Detection": repeated denied
 * attempts by the same agent in a short window must produce a warning incident and audit event,
 * without changing the underlying DENY decisions themselves (baselines observe, they don't block).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class BehaviorBaselineIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private IncidentRepository incidentRepository;
    @Autowired
    private AuditEventRepository auditEventRepository;
    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void repeatedDenialsInAShortWindowCreateAWarningIncident() {
        String plaintextToken = "baseline-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("baseline-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("filesystem");
        agent = agentRepository.save(agent);
        Agent savedAgent = agent;

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        // Agent is only allowed "filesystem" but this tool is in "database" — every call is DENY.
        Tool tool = new Tool();
        tool.setName("baseline-tool-" + System.nanoTime());
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
        TestRestTemplate rest = new TestRestTemplate();

        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "lookupRecords");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("key", "value"));

        long threshold = BaselineThresholds.defaults().denialThreshold();
        for (int i = 0; i < threshold; i++) {
            rest.postForEntity("http://localhost:" + port + "/api/gateway/invoke", new HttpEntity<>(body, headers), String.class);
        }

        List<Incident> warnings = incidentRepository.findAll().stream()
                .filter(inc -> inc.getSeverity() == AuditSeverity.WARNING)
                .filter(inc -> inc.getTitle().contains(savedAgent.getName()))
                .toList();
        assertThat(warnings).isNotEmpty();
        assertThat(warnings).anyMatch(inc -> inc.getSummary().contains("denied attempts"));

        assertThat(auditEventRepository.findAll().stream()
                .anyMatch(e -> "behavior.anomaly_detected".equals(e.getEventType()) && savedAgent.getId().equals(e.getAgentId())))
                .isTrue();
    }
}
