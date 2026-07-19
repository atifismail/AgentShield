package com.agentshield.behavior;

/**
 * Fixed, documented thresholds for the deterministic behavior-baseline checks
 * (improvement_plan.md P2 "Agent Behavior Baselines And Anomaly Detection"). No machine learning
 * and no LLM output is involved — every check here is a simple counting/ratio rule over existing
 * gateway history, so a given input always produces the same finding.
 */
public record BaselineThresholds(
        long minPriorRequestsForVolumeCheck,
        long volumeSpikeFloor,
        double volumeSpikeMultiplier,
        long denialWindowMinutes,
        long denialThreshold,
        long approvalFrequencyWindowMinutes,
        long approvalFrequencyThreshold,
        long minPriorRequestsForNoveltyCheck
) {
    public static BaselineThresholds defaults() {
        // minPriorRequestsForNoveltyCheck: a brand-new agent's first few actions are always
        // "first seen" and not meaningfully anomalous — only flag novelty once the agent has an
        // established pattern to deviate from.
        return new BaselineThresholds(5, 20, 5.0, 15, 5, 60, 5, 10);
    }
}
