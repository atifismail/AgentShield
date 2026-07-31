package com.agentshield.grant;

import com.agentshield.common.ActionCategory;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Matches an agent/tool pair's grants against a resolved gateway request
 * (agentshield_policy_evidence_execution_plan_2026-07-30.md work package 2). Read live from the
 * database on every call — no caching — so a revoke is honored on the very next invocation
 * (invariant: "concurrent grant revoke versus invocation fails closed at the authorization
 * boundary").
 */
@Service
public class GrantEvaluationService {

    private final AgentToolGrantRepository repository;

    public GrantEvaluationService(AgentToolGrantRepository repository) {
        this.repository = repository;
    }

    public GrantDecision evaluate(Long agentId, Long toolId, ActionCategory actionCategory, String targetEnvironment,
            NormalizedAuthorizationFacts facts, GrantTransitionMode mode) {
        if (mode == GrantTransitionMode.GROUPS_ONLY) {
            return GrantDecision.NOT_APPLICABLE;
        }
        List<AgentToolGrant> grants = repository.findByAgentIdAndToolId(agentId, toolId);
        if (mode == GrantTransitionMode.GRANTS_OR_GROUPS && grants.isEmpty()) {
            return GrantDecision.NOT_APPLICABLE;
        }
        Instant now = Instant.now();
        boolean matched = grants.stream().anyMatch(grant -> matches(grant, now, actionCategory, targetEnvironment, facts));
        return matched ? GrantDecision.SATISFIED : GrantDecision.DENIED;
    }

    private boolean matches(AgentToolGrant grant, Instant now, ActionCategory actionCategory, String targetEnvironment,
            NormalizedAuthorizationFacts facts) {
        if (grant.getStatus() != GrantStatus.ACTIVE) {
            return false;
        }
        if (!grant.isWithinTimeWindow(now)) {
            return false;
        }
        if (grant.getActionCategory() != null && grant.getActionCategory() != actionCategory) {
            return false;
        }
        if (grant.getTargetEnvironment() != null && !grant.getTargetEnvironment().equalsIgnoreCase(targetEnvironment)) {
            return false;
        }
        if (grant.getResourcePathPattern() != null) {
            if (facts.resourcePath() == null
                    || !ResourcePathPatternValidator.matches(grant.getResourcePathPattern(), facts.resourcePath())) {
                return false;
            }
        }
        if (grant.getRequiredTokenScope() != null && !facts.tokenScopes().contains(grant.getRequiredTokenScope())) {
            return false;
        }
        return true;
    }
}
