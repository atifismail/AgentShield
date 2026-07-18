package com.agentshield.policy;

import com.agentshield.common.PolicyDecisionType;

public record PolicyOutcome(PolicyDecisionType decision, String reason, String ruleId) {

    public static PolicyOutcome allow() {
        return new PolicyOutcome(PolicyDecisionType.ALLOW, "no policy rule matched", "allow-default");
    }

    public boolean isAllow() {
        return decision == PolicyDecisionType.ALLOW;
    }
}
