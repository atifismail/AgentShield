package com.agentshield.policy;

import com.agentshield.agent.Agent;
import com.agentshield.common.ActionCategory;
import com.agentshield.tool.Tool;

/** Facts the pre-call policy rules are evaluated against. The tool must already be resolved. */
public record PolicyEvaluationContext(
        Agent agent,
        Tool tool,
        ActionCategory actionCategory,
        String targetEnvironment,
        int payloadSizeBytes,
        int maxPayloadSizeBytes
) {

    public boolean isProd() {
        return "PROD".equalsIgnoreCase(targetEnvironment);
    }
}
