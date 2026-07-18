package com.agentshield.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.support.AbstractIntegrationTest;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AgentCredentialServiceTest extends AbstractIntegrationTest {

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository credentialRepository;
    @Autowired
    private AgentCredentialService credentialService;

    private Agent newAgent() {
        Agent agent = new Agent();
        agent.setName("cred-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        return agentRepository.save(agent);
    }

    @Test
    void createIssuesPlaintextTokenOnlyOnceAndStoresOnlyItsHash() {
        Agent agent = newAgent();
        var issued = credentialService.create(agent.getId(), "tester", null);

        assertThat(issued.plaintextToken()).isNotBlank();
        AgentCredential stored = credentialRepository.findById(issued.credentialId()).orElseThrow();
        assertThat(stored.getTokenHash()).isNotEqualTo(issued.plaintextToken());
        assertThat(stored.getStatus()).isEqualTo(CredentialStatus.ACTIVE);
        assertThat(stored.getTokenPrefix()).isNotBlank().doesNotContain(issued.plaintextToken().substring(8));
    }

    @Test
    void revokeMarksCredentialUnusable() {
        Agent agent = newAgent();
        var issued = credentialService.create(agent.getId(), "tester", null);

        credentialService.revoke(issued.credentialId(), "security-analyst");

        AgentCredential stored = credentialRepository.findById(issued.credentialId()).orElseThrow();
        assertThat(stored.getStatus()).isEqualTo(CredentialStatus.REVOKED);
        assertThat(stored.isUsable(Instant.now())).isFalse();
    }

    @Test
    void rotateRevokesAllActiveCredentialsAndIssuesOne() {
        Agent agent = newAgent();
        var first = credentialService.create(agent.getId(), "tester", null);
        var second = credentialService.create(agent.getId(), "tester", null);

        var rotated = credentialService.rotate(agent.getId(), "security-analyst");

        assertThat(credentialRepository.findById(first.credentialId()).orElseThrow().getStatus())
                .isEqualTo(CredentialStatus.REVOKED);
        assertThat(credentialRepository.findById(second.credentialId()).orElseThrow().getStatus())
                .isEqualTo(CredentialStatus.REVOKED);
        assertThat(credentialRepository.findById(rotated.credentialId()).orElseThrow().getStatus())
                .isEqualTo(CredentialStatus.ACTIVE);
    }

    @Test
    void expireOverdueCredentialsSweepsPastExpiry() {
        Agent agent = newAgent();
        var issued = credentialService.create(agent.getId(), "tester", Duration.ofMillis(1));

        // force it into the past so the sweep picks it up regardless of clock resolution
        AgentCredential credential = credentialRepository.findById(issued.credentialId()).orElseThrow();
        credential.setExpiresAt(Instant.now().minusSeconds(1));
        credentialRepository.saveAndFlush(credential);

        credentialService.expireOverdueCredentials();

        assertThat(credentialRepository.findById(issued.credentialId()).orElseThrow().getStatus())
                .isEqualTo(CredentialStatus.EXPIRED);
    }

    @Test
    void listForAgentNeverExposesFullToken() {
        Agent agent = newAgent();
        credentialService.create(agent.getId(), "tester", null);

        var list = credentialService.listForAgent(agent.getId());
        assertThat(list).hasSize(1);
        assertThat(list.get(0).getTokenPrefix().length()).isLessThan(list.get(0).getTokenHash().length());
    }
}
