package com.agentshield.behavior;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure, deterministic behavior-baseline checks — no LLM output is ever treated as authoritative
 * here (improvement_plan.md P2 "Agent Behavior Baselines And Anomaly Detection", and the
 * project's non-negotiable rule against LLM-authoritative security decisions). Every rule is a
 * plain counting/ratio comparison so the same {@link BaselineInputs} always yields the same
 * findings, and each rule is independently unit-testable without a database or a clock mock
 * beyond a fixed {@code now}.
 */
public final class BehaviorBaselineRules {

    private BehaviorBaselineRules() {
    }

    public static List<BaselineFinding> evaluate(BaselineInputs in, BaselineThresholds t, Instant now) {
        List<BaselineFinding> findings = new ArrayList<>();

        if (in.firstTimeCombination() && in.totalPriorRequestsForAgent() >= t.minPriorRequestsForNoveltyCheck()) {
            findings.add(new BaselineFinding("first_seen_combination",
                    "first time this established agent has called this tool/action/environment combination"));
        }

        if (in.denialsInDenialWindow() >= t.denialThreshold()) {
            findings.add(new BaselineFinding("repeated_denials",
                    in.denialsInDenialWindow() + " denied attempts in the last " + t.denialWindowMinutes() + " minute(s)"));
        }

        if (in.approvalRequiredInFrequencyWindow() >= t.approvalFrequencyThreshold()) {
            findings.add(new BaselineFinding("unusual_approval_frequency",
                    in.approvalRequiredInFrequencyWindow() + " approval-required actions in the last "
                            + t.approvalFrequencyWindowMinutes() + " minute(s)"));
        }

        if (in.totalPriorRequestsForAgent() >= t.minPriorRequestsForVolumeCheck()) {
            double hoursOfHistory = Math.max(1.0,
                    Duration.between(in.agentFirstRequestAt(), now).toMinutes() / 60.0);
            double averageHourlyVolume = in.totalPriorRequestsForAgent() / hoursOfHistory;
            double spikeThreshold = Math.max(t.volumeSpikeFloor(), averageHourlyVolume * t.volumeSpikeMultiplier());
            if (in.requestsInTrailingHour() > spikeThreshold) {
                findings.add(new BaselineFinding("volume_spike",
                        in.requestsInTrailingHour() + " requests in the trailing hour, versus a baseline average of "
                                + String.format("%.1f", averageHourlyVolume) + " per hour"));
            }
        }

        return findings;
    }
}
