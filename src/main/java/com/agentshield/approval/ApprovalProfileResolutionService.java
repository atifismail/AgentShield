package com.agentshield.approval;

import com.agentshield.agent.Agent;
import com.agentshield.common.ActionCategory;
import com.agentshield.tool.Tool;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Selects the routing profile for an already-{@code APPROVAL_REQUIRED} request
 * (agentshield_policy_evidence_execution_plan_2026-07-30.md work package 3, "Resolution
 * algorithm"). Only ever called after the fixed policy rules and grants have already decided
 * {@code APPROVAL_REQUIRED} — this never changes that decision, it only routes it.
 */
@Service
public class ApprovalProfileResolutionService {

    private final ApprovalProfileRepository repository;

    public ApprovalProfileResolutionService(ApprovalProfileRepository repository) {
        this.repository = repository;
    }

    public Optional<ApprovalProfile> resolve(Agent agent, Tool tool, ActionCategory actionCategory,
            String targetEnvironment) {
        List<ApprovalProfile> candidates = repository.findByEnabledTrueOrderByPriorityDesc();
        return candidates.stream().filter(profile -> matches(profile, agent, tool, actionCategory, targetEnvironment))
                .findFirst();
    }

    private boolean matches(ApprovalProfile profile, Agent agent, Tool tool, ActionCategory actionCategory,
            String targetEnvironment) {
        if (profile.getAgentId() != null && !profile.getAgentId().equals(agent.getId())) {
            return false;
        }
        if (profile.getToolId() != null && !profile.getToolId().equals(tool.getId())) {
            return false;
        }
        if (profile.getToolGroup() != null && !profile.getToolGroup().equalsIgnoreCase(tool.getToolGroup())) {
            return false;
        }
        if (profile.getActionCategory() != null && profile.getActionCategory() != actionCategory) {
            return false;
        }
        if (profile.getTargetEnvironment() != null
                && !profile.getTargetEnvironment().equalsIgnoreCase(targetEnvironment)) {
            return false;
        }
        return profile.getRiskTier() == null || profile.getRiskTier() == tool.getRiskTier();
    }
}
