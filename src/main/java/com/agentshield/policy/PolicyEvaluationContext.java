package com.agentshield.policy;

import com.agentshield.agent.Agent;
import com.agentshield.common.ActionCategory;
import com.agentshield.grant.NormalizedAuthorizationFacts;
import com.agentshield.tool.Tool;

/** Facts the pre-call policy rules are evaluated against. The tool must already be resolved. */
public record PolicyEvaluationContext(
        Agent agent,
        Tool tool,
        ActionCategory actionCategory,
        String targetEnvironment,
        int payloadSizeBytes,
        int maxPayloadSizeBytes,
        NormalizedAuthorizationFacts authorizationFacts
) {

    /** Convenience constructor for callers/tests that don't need grant resource/scope matching. */
    public PolicyEvaluationContext(Agent agent, Tool tool, ActionCategory actionCategory, String targetEnvironment,
            int payloadSizeBytes, int maxPayloadSizeBytes) {
        this(agent, tool, actionCategory, targetEnvironment, payloadSizeBytes, maxPayloadSizeBytes,
                NormalizedAuthorizationFacts.EMPTY);
    }

    public boolean isProd() {
        return "PROD".equalsIgnoreCase(targetEnvironment);
    }
}
