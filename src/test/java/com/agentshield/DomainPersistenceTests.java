package com.agentshield;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.AgentRepository;
import com.agentshield.policy.PolicyRepository;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.ToolRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DomainPersistenceTests extends AbstractIntegrationTest {

    @Autowired
    private AgentRepository agentRepository;

    @Autowired
    private ToolRepository toolRepository;

    @Autowired
    private PolicyRepository policyRepository;

    @Test
    void seedDataIsLoadedByMigrations() {
        // Other test classes share this same database (singleton Testcontainer), so assert
        // presence of the seeded rows rather than exact totals.
        assertThat(agentRepository.findByName("coding-agent-01")).isPresent();
        assertThat(agentRepository.findByName("support-assistant-01")).isPresent();
        assertThat(agentRepository.findByName("retired-agent-01")).isPresent();
        assertThat(toolRepository.findByName("mock-database")).isPresent();
        assertThat(toolRepository.findByName("mock-git")).isPresent();
        assertThat(toolRepository.findByName("mock-filesystem")).isPresent();
        assertThat(toolRepository.findByName("mock-saas-crm")).isPresent();
        assertThat(policyRepository.findByNameOrderByVersionDesc("default-policy")).isNotEmpty();
    }

    @Test
    void agentAllowedToolGroupsParsesCommaSeparatedList() {
        var agent = agentRepository.findByName("coding-agent-01").orElseThrow();
        assertThat(agent.allowedToolGroupSet()).contains("source-control", "filesystem", "database");
    }

    @Test
    void toolDriftDetectionComparesHashes() {
        var tool = toolRepository.findByName("mock-git").orElseThrow();
        assertThat(tool.hasDrift()).isFalse();
        tool.setCurrentHash("changed-hash");
        assertThat(tool.hasDrift()).isTrue();
    }
}
