package com.agentshield.policy;

import com.agentshield.risk.DetectionResult;

/**
 * Extension point (improvement_plan.md #8): {@link PolicyEngine} is the default, always-on
 * implementation (fixed Java rules + database-backed overrides). {@link OpaPolicyEvaluator} is a
 * documented-but-unimplemented stub for a future OPA sidecar — not required for local MVP, and
 * not wired into Spring, so it has no effect on runtime behavior today.
 */
public interface PolicyEvaluator {

    PolicyOutcome evaluateRequest(PolicyEvaluationContext ctx);

    PolicyOutcome evaluateResponse(boolean destinationIsExternal, DetectionResult secretResult,
            DetectionResult injectionResult);
}
