package com.agentshield.approval;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.common.ActionCategory;
import com.agentshield.security.UserRole;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolRiskTier;
import com.agentshield.tool.ToolType;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 3, "Required tests":
 * highest-priority match wins, and every predicate narrows correctly.
 */
class ApprovalProfileResolutionServiceTest {

    private final ApprovalProfileRepository repository = Mockito.mock(ApprovalProfileRepository.class);
    private final ApprovalProfileResolutionService service = new ApprovalProfileResolutionService(repository);

    private Agent agent(Long id) {
        Agent agent = new Agent();
        agent.setId(id);
        agent.setName("agent-" + id);
        return agent;
    }

    private Tool tool(Long id, String group, ToolRiskTier riskTier) {
        Tool tool = new Tool();
        tool.setId(id);
        tool.setName("tool-" + id);
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup(group);
        tool.setRiskTier(riskTier);
        return tool;
    }

    private ApprovalProfile profile(int priority, UserRole role) {
        ApprovalProfile profile = new ApprovalProfile();
        profile.setId((long) priority);
        profile.setName("profile-" + priority);
        profile.setPriority(priority);
        profile.setEnabled(true);
        profile.setTargetRole(role);
        return profile;
    }

    @Test
    void highestPriorityEnabledMatchingProfileWins() {
        ApprovalProfile low = profile(10, UserRole.APPROVER);
        ApprovalProfile high = profile(100, UserRole.SECURITY_ANALYST);
        // Repository contract: already ordered by priority descending.
        Mockito.when(repository.findByEnabledTrueOrderByPriorityDesc()).thenReturn(List.of(high, low));

        Optional<ApprovalProfile> resolved = service.resolve(agent(1L), tool(2L, "db", ToolRiskTier.UNCLASSIFIED),
                ActionCategory.READ, "DEV");

        assertThat(resolved).contains(high);
    }

    @Test
    void agentPredicateNarrowsToTheExactAgent() {
        ApprovalProfile scoped = profile(10, UserRole.APPROVER);
        scoped.setAgentId(1L);
        Mockito.when(repository.findByEnabledTrueOrderByPriorityDesc()).thenReturn(List.of(scoped));

        assertThat(service.resolve(agent(1L), tool(2L, "db", ToolRiskTier.UNCLASSIFIED), ActionCategory.READ, "DEV"))
                .contains(scoped);
        assertThat(service.resolve(agent(99L), tool(2L, "db", ToolRiskTier.UNCLASSIFIED), ActionCategory.READ, "DEV"))
                .isEmpty();
    }

    @Test
    void toolPredicateNarrowsToTheExactTool() {
        ApprovalProfile scoped = profile(10, UserRole.APPROVER);
        scoped.setToolId(2L);
        Mockito.when(repository.findByEnabledTrueOrderByPriorityDesc()).thenReturn(List.of(scoped));

        assertThat(service.resolve(agent(1L), tool(99L, "db", ToolRiskTier.UNCLASSIFIED), ActionCategory.READ, "DEV"))
                .isEmpty();
    }

    @Test
    void toolGroupPredicateIsCaseInsensitive() {
        ApprovalProfile scoped = profile(10, UserRole.APPROVER);
        scoped.setToolGroup("Database");
        Mockito.when(repository.findByEnabledTrueOrderByPriorityDesc()).thenReturn(List.of(scoped));

        assertThat(service.resolve(agent(1L), tool(2L, "database", ToolRiskTier.UNCLASSIFIED), ActionCategory.READ,
                "DEV")).contains(scoped);
    }

    @Test
    void actionCategoryPredicateNarrows() {
        ApprovalProfile scoped = profile(10, UserRole.APPROVER);
        scoped.setActionCategory(ActionCategory.WRITE);
        Mockito.when(repository.findByEnabledTrueOrderByPriorityDesc()).thenReturn(List.of(scoped));

        assertThat(service.resolve(agent(1L), tool(2L, "db", ToolRiskTier.UNCLASSIFIED), ActionCategory.READ, "DEV"))
                .isEmpty();
    }

    @Test
    void environmentPredicateIsCaseInsensitive() {
        ApprovalProfile scoped = profile(10, UserRole.APPROVER);
        scoped.setTargetEnvironment("prod");
        Mockito.when(repository.findByEnabledTrueOrderByPriorityDesc()).thenReturn(List.of(scoped));

        assertThat(service.resolve(agent(1L), tool(2L, "db", ToolRiskTier.UNCLASSIFIED), ActionCategory.READ, "PROD"))
                .contains(scoped);
    }

    @Test
    void riskTierPredicateNarrows() {
        ApprovalProfile scoped = profile(10, UserRole.APPROVER);
        scoped.setRiskTier(ToolRiskTier.CRITICAL);
        Mockito.when(repository.findByEnabledTrueOrderByPriorityDesc()).thenReturn(List.of(scoped));

        assertThat(service.resolve(agent(1L), tool(2L, "db", ToolRiskTier.LOW), ActionCategory.READ, "DEV")).isEmpty();
        assertThat(service.resolve(agent(1L), tool(2L, "db", ToolRiskTier.CRITICAL), ActionCategory.READ, "DEV"))
                .contains(scoped);
    }

    @Test
    void noMatchingProfileResolvesEmpty() {
        Mockito.when(repository.findByEnabledTrueOrderByPriorityDesc()).thenReturn(List.of());

        assertThat(service.resolve(agent(1L), tool(2L, "db", ToolRiskTier.UNCLASSIFIED), ActionCategory.READ, "DEV"))
                .isEmpty();
    }
}
