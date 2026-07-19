package com.agentshield.policy;

import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.PolicyMode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public final class PolicyDtos {

    private PolicyDtos() {
    }

    public record CreateVersionRequest(@NotBlank String name, String ruleJson, PolicyMode mode, String createdBy) {
    }

    public record PolicyResponse(Long id, String name, int version, boolean enabled, PolicyMode mode,
            String ruleJson, String createdBy, Instant createdAt) {
        public static PolicyResponse from(Policy policy) {
            return new PolicyResponse(policy.getId(), policy.getName(), policy.getVersion(), policy.isEnabled(),
                    policy.getMode(), policy.getRuleJson(), policy.getCreatedBy(), policy.getCreatedAt());
        }
    }

    /**
     * Evaluates a hypothetical request through the live default rule set without persisting a
     * GatewayRequest or any audit trail. The stored {@code rule_json} on {@link Policy} is
     * versioned metadata for review/rollback; the rules that actually run are the fixed default
     * Java rules in {@link PolicyEngine} for this release (PROJECT_PLAN.md section 2: "Start with
     * embedded policy evaluation in Java").
     */
    public record DryRunRequest(
            @NotNull Long agentId,
            @NotNull Long toolId,
            @NotNull ActionCategory actionCategory,
            String targetEnvironment,
            int payloadSizeBytes
    ) {
    }

    public record DryRunResponse(PolicyDecisionType decision, String reason, String ruleId) {
        public static DryRunResponse from(PolicyOutcome outcome) {
            return new DryRunResponse(outcome.decision(), outcome.reason(), outcome.ruleId());
        }
    }

    /**
     * Policy simulation/replay lab (improvement_plan.md P3): re-evaluates a historical gateway
     * request's facts (agent, tool, action category, target environment, payload size) against
     * the live policy engine — including any policy overrides in force right now — without
     * touching the downstream tool or persisting anything. Shows what would happen today versus
     * what actually happened at the time.
     */
    public record ReplayResponse(
            Long gatewayRequestId,
            PolicyDecisionType originalDecision,
            String originalReason,
            PolicyDecisionType simulatedDecision,
            String simulatedReason,
            String simulatedRuleId,
            boolean decisionChanged
    ) {
    }
}
