package com.agentshield.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.mcp.McpConsentDtos.CreateConsentRequest;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.support.AbstractIntegrationTest;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/** design-mcp-authorization.md §11 — consent lifecycle and the "null means any" scoping rules. */
@SpringBootTest
class McpConsentServiceTest extends AbstractIntegrationTest {

    @Autowired
    private McpConsentService consentService;
    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private McpDiscoveryService discoveryService;

    private Agent createAgent() {
        Agent agent = new Agent();
        agent.setName("consent-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        return agentRepository.save(agent);
    }

    private McpServer createServer() {
        return discoveryService.register(new RegisterMcpServerRequest(
                "consent-test-server-" + System.nanoTime(), McpTransportType.HTTP,
                "http://localhost:1/unused", null, null, null, "owner", "DEV", "mcp"));
    }

    @Test
    void wholeServerGrantCoversAnyToolAndCategory() {
        Agent agent = createAgent();
        McpServer server = createServer();
        consentService.create(new CreateConsentRequest(agent.getId(), server.getId(), null, null, null), "admin");

        assertThat(consentService.hasActiveConsent(agent.getId(), server.getId(), "any-tool", ActionCategory.WRITE))
                .isTrue();
    }

    @Test
    void toolScopedGrantDoesNotCoverADifferentTool() {
        Agent agent = createAgent();
        McpServer server = createServer();
        consentService.create(new CreateConsentRequest(agent.getId(), server.getId(), "echo", null, null), "admin");

        assertThat(consentService.hasActiveConsent(agent.getId(), server.getId(), "echo", ActionCategory.READ)).isTrue();
        assertThat(consentService.hasActiveConsent(agent.getId(), server.getId(), "other-tool", ActionCategory.READ))
                .isFalse();
    }

    @Test
    void categoryScopedGrantDoesNotCoverADifferentCategory() {
        Agent agent = createAgent();
        McpServer server = createServer();
        consentService.create(new CreateConsentRequest(agent.getId(), server.getId(), null, ActionCategory.READ, null),
                "admin");

        assertThat(consentService.hasActiveConsent(agent.getId(), server.getId(), "echo", ActionCategory.READ)).isTrue();
        assertThat(consentService.hasActiveConsent(agent.getId(), server.getId(), "echo", ActionCategory.WRITE))
                .isFalse();
    }

    @Test
    void revokingAConsentImmediatelyRemovesAccess() {
        Agent agent = createAgent();
        McpServer server = createServer();
        McpConsent consent = consentService.create(
                new CreateConsentRequest(agent.getId(), server.getId(), null, null, null), "admin");
        assertThat(consentService.hasActiveConsent(agent.getId(), server.getId(), "echo", ActionCategory.READ)).isTrue();

        consentService.revoke(consent.getId(), "security-analyst-1");

        assertThat(consentService.hasActiveConsent(agent.getId(), server.getId(), "echo", ActionCategory.READ))
                .isFalse();
    }

    @Test
    void expiredConsentDoesNotGrantAccessEvenBeforeTheSweepRuns() {
        Agent agent = createAgent();
        McpServer server = createServer();
        consentService.create(new CreateConsentRequest(agent.getId(), server.getId(), null, null,
                Instant.now().minusSeconds(60)), "admin");

        // Not yet swept to EXPIRED by the scheduled job, but the matching query itself already
        // excludes it — a consent must never be usable past its expiry even for a brief window.
        assertThat(consentService.hasActiveConsent(agent.getId(), server.getId(), "echo", ActionCategory.READ))
                .isFalse();
    }

    @Test
    void expireOverdueConsentsSweepsPastExpiryRowsToExpiredStatus() {
        Agent agent = createAgent();
        McpServer server = createServer();
        McpConsent consent = consentService.create(new CreateConsentRequest(agent.getId(), server.getId(), null, null,
                Instant.now().minusSeconds(60)), "admin");

        consentService.expireOverdueConsents();

        assertThat(consentService.listForAgent(agent.getId()).stream()
                .filter(c -> c.getId().equals(consent.getId())).findFirst().orElseThrow().getStatus())
                .isEqualTo(ConsentStatus.EXPIRED);
    }

    @Test
    void twoAgentsWithSeparateGrantsToTheSameServerDoNotAffectEachOther() {
        Agent agentOne = createAgent();
        Agent agentTwo = createAgent();
        McpServer server = createServer();
        McpConsent consentOne = consentService.create(
                new CreateConsentRequest(agentOne.getId(), server.getId(), null, null, null), "admin");
        consentService.create(new CreateConsentRequest(agentTwo.getId(), server.getId(), null, null, null), "admin");

        consentService.revoke(consentOne.getId(), "security-analyst-1");

        assertThat(consentService.hasActiveConsent(agentOne.getId(), server.getId(), "echo", ActionCategory.READ))
                .isFalse();
        assertThat(consentService.hasActiveConsent(agentTwo.getId(), server.getId(), "echo", ActionCategory.READ))
                .isTrue();
    }
}
