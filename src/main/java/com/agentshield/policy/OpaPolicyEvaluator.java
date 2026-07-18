package com.agentshield.policy;

import com.agentshield.risk.DetectionResult;

/**
 * Extension point for a future Open Policy Agent sidecar integration (PROJECT_PLAN.md section 2:
 * "Add external OPA sidecar integration after core gateway works"). Not implemented, and
 * deliberately not a Spring bean — instantiating and wiring this in is future work, gated behind
 * whatever config makes OPA opt-in, since AgentShield must not require a paid or external service
 * for its MVP (AGENTS.md rule 1, improvement_plan.md #8: "do not require OPA for local MVP").
 */
public class OpaPolicyEvaluator implements PolicyEvaluator {

    @Override
    public PolicyOutcome evaluateRequest(PolicyEvaluationContext ctx) {
        throw new UnsupportedOperationException(
                "OPA integration is not implemented. Use PolicyEngine, the default Java evaluator.");
    }

    @Override
    public PolicyOutcome evaluateResponse(boolean destinationIsExternal, DetectionResult secretResult,
            DetectionResult injectionResult) {
        throw new UnsupportedOperationException(
                "OPA integration is not implemented. Use PolicyEngine, the default Java evaluator.");
    }
}
