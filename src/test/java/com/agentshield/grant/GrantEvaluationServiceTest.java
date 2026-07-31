package com.agentshield.grant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.agentshield.common.ActionCategory;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 2, "Required tests" for
 * {@code GrantEvaluationService}: exact match, wrong action/environment/resource/scope, expired/
 * revoked/future/duplicate-overlapping grants, and the GROUPS_ONLY/GRANTS_OR_GROUPS short-circuits.
 */
class GrantEvaluationServiceTest {

    private final AgentToolGrantRepository repository = Mockito.mock(AgentToolGrantRepository.class);
    private final GrantEvaluationService service = new GrantEvaluationService(repository);

    private AgentToolGrant grant() {
        AgentToolGrant grant = new AgentToolGrant();
        grant.setAgentId(1L);
        grant.setToolId(2L);
        grant.setStatus(GrantStatus.ACTIVE);
        return grant;
    }

    @Test
    void groupsOnlyModeIsAlwaysNotApplicableRegardlessOfGrants() {
        var decision = service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GROUPS_ONLY);
        assertThat(decision).isEqualTo(GrantDecision.NOT_APPLICABLE);
        Mockito.verifyNoInteractions(repository);
    }

    @Test
    void grantsRequiredWithNoGrantsAtAllDenies() {
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of());

        var decision = service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED);

        assertThat(decision).isEqualTo(GrantDecision.DENIED);
    }

    @Test
    void grantsOrGroupsWithNoGrantsAtAllFallsBackToGroupCheck() {
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of());

        var decision = service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_OR_GROUPS);

        assertThat(decision).isEqualTo(GrantDecision.NOT_APPLICABLE);
    }

    @Test
    void exactActiveGrantAllowsOnlyItsNamedActionAndEnvironment() {
        AgentToolGrant g = grant();
        g.setActionCategory(ActionCategory.READ);
        g.setTargetEnvironment("DEV");
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.SATISFIED);
    }

    @Test
    void wrongActionCategoryDenies() {
        AgentToolGrant g = grant();
        g.setActionCategory(ActionCategory.READ);
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        assertThat(service.evaluate(1L, 2L, ActionCategory.WRITE, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.DENIED);
    }

    @Test
    void wrongEnvironmentDenies() {
        AgentToolGrant g = grant();
        g.setTargetEnvironment("DEV");
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "PROD", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.DENIED);
    }

    @Test
    void environmentMatchIsCaseInsensitive() {
        AgentToolGrant g = grant();
        g.setTargetEnvironment("dev");
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.SATISFIED);
    }

    @Test
    void wrongResourcePathDenies() {
        AgentToolGrant g = grant();
        g.setResourcePathPattern("/repos/*/pulls");
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        var wrongPath = new NormalizedAuthorizationFacts("/repos/other/issues", Set.of());
        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", wrongPath, GrantTransitionMode.GRANTS_REQUIRED))
                .isEqualTo(GrantDecision.DENIED);
    }

    @Test
    void aResourceRestrictedGrantDeniesWhenNoResourcePathWasEstablished() {
        AgentToolGrant g = grant();
        g.setResourcePathPattern("/repos/*/pulls");
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        // Facts never established a resourcePath (no reviewed normalizer for this tool) — a
        // restriction must never be satisfied by absence of the fact it restricts on.
        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.DENIED);
    }

    @Test
    void matchingResourcePathAllows() {
        AgentToolGrant g = grant();
        g.setResourcePathPattern("/repos/*/pulls");
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        var facts = new NormalizedAuthorizationFacts("/repos/agentshield/pulls", Set.of());
        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", facts, GrantTransitionMode.GRANTS_REQUIRED))
                .isEqualTo(GrantDecision.SATISFIED);
    }

    @Test
    void wrongTokenScopeDeniesAndScopeMatchIsExactNotSubstring() {
        AgentToolGrant g = grant();
        g.setRequiredTokenScope("repo:read");
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        var wrongScope = new NormalizedAuthorizationFacts(null, Set.of("repo:read:extra", "repo"));
        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", wrongScope, GrantTransitionMode.GRANTS_REQUIRED))
                .isEqualTo(GrantDecision.DENIED);

        var exactScope = new NormalizedAuthorizationFacts(null, Set.of("repo:read"));
        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", exactScope, GrantTransitionMode.GRANTS_REQUIRED))
                .isEqualTo(GrantDecision.SATISFIED);
    }

    @Test
    void revokedGrantNeverMatches() {
        AgentToolGrant g = grant();
        g.setStatus(GrantStatus.REVOKED);
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.DENIED);
    }

    @Test
    void expiredGrantNeverMatches() {
        AgentToolGrant g = grant();
        g.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.DENIED);
    }

    @Test
    void futureGrantNotYetActiveNeverMatches() {
        AgentToolGrant g = grant();
        g.setNotBefore(Instant.now().plus(1, ChronoUnit.HOURS));
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(g));

        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.DENIED);
    }

    @Test
    void duplicateOverlappingGrantsAllowIfAnyOneOfThemMatches() {
        AgentToolGrant wrongOne = grant();
        wrongOne.setActionCategory(ActionCategory.WRITE);
        AgentToolGrant matchingOne = grant();
        matchingOne.setActionCategory(ActionCategory.READ);
        when(repository.findByAgentIdAndToolId(1L, 2L)).thenReturn(List.of(wrongOne, matchingOne));

        assertThat(service.evaluate(1L, 2L, ActionCategory.READ, "DEV", NormalizedAuthorizationFacts.EMPTY,
                GrantTransitionMode.GRANTS_REQUIRED)).isEqualTo(GrantDecision.SATISFIED);
    }
}
