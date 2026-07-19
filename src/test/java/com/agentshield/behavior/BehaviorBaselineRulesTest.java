package com.agentshield.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class BehaviorBaselineRulesTest {

    private final BaselineThresholds thresholds = BaselineThresholds.defaults();
    private final Instant now = Instant.parse("2026-07-19T12:00:00Z");

    @Test
    void quietAgentProducesNoFindings() {
        BaselineInputs inputs = new BaselineInputs(false, 10, now.minus(Duration.ofDays(30)), 3, 0, 0);

        assertThat(BehaviorBaselineRules.evaluate(inputs, thresholds, now)).isEmpty();
    }

    @Test
    void firstSeenCombinationIsFlaggedForAnEstablishedAgent() {
        BaselineInputs inputs = new BaselineInputs(true, thresholds.minPriorRequestsForNoveltyCheck(),
                now.minus(Duration.ofDays(30)), 3, 0, 0);

        List<BaselineFinding> findings = BehaviorBaselineRules.evaluate(inputs, thresholds, now);

        assertThat(findings).extracting(BaselineFinding::code).contains("first_seen_combination");
    }

    @Test
    void firstSeenCombinationIsNotFlaggedForABrandNewAgent() {
        // A brand-new agent's very first few actions are always "first seen" — not anomalous.
        BaselineInputs inputs = new BaselineInputs(true, thresholds.minPriorRequestsForNoveltyCheck() - 1,
                now.minus(Duration.ofMinutes(1)), 1, 0, 0);

        assertThat(BehaviorBaselineRules.evaluate(inputs, thresholds, now)).isEmpty();
    }

    @Test
    void repeatedDenialsAtThresholdAreFlagged() {
        BaselineInputs inputs = new BaselineInputs(false, 10, now.minus(Duration.ofDays(30)), 3,
                thresholds.denialThreshold(), 0);

        List<BaselineFinding> findings = BehaviorBaselineRules.evaluate(inputs, thresholds, now);

        assertThat(findings).extracting(BaselineFinding::code).contains("repeated_denials");
    }

    @Test
    void denialsBelowThresholdAreNotFlagged() {
        BaselineInputs inputs = new BaselineInputs(false, 10, now.minus(Duration.ofDays(30)), 3,
                thresholds.denialThreshold() - 1, 0);

        assertThat(BehaviorBaselineRules.evaluate(inputs, thresholds, now)).isEmpty();
    }

    @Test
    void unusualApprovalFrequencyIsFlagged() {
        BaselineInputs inputs = new BaselineInputs(false, 10, now.minus(Duration.ofDays(30)), 3, 0,
                thresholds.approvalFrequencyThreshold());

        List<BaselineFinding> findings = BehaviorBaselineRules.evaluate(inputs, thresholds, now);

        assertThat(findings).extracting(BaselineFinding::code).contains("unusual_approval_frequency");
    }

    @Test
    void volumeSpikeIsFlaggedAgainstHistoricalAverage() {
        // 240 requests over 30 days of history => average 10/hour baseline; 100 in the trailing
        // hour is a clear spike against max(floor=20, 10 * 5 = 50).
        BaselineInputs inputs = new BaselineInputs(false, 240, now.minus(Duration.ofDays(30)), 100, 0, 0);

        List<BaselineFinding> findings = BehaviorBaselineRules.evaluate(inputs, thresholds, now);

        assertThat(findings).extracting(BaselineFinding::code).contains("volume_spike");
    }

    @Test
    void volumeCheckIsSkippedWithoutEnoughHistory() {
        BaselineInputs inputs = new BaselineInputs(false, thresholds.minPriorRequestsForVolumeCheck() - 1,
                now.minus(Duration.ofDays(30)), 1000, 0, 0);

        assertThat(BehaviorBaselineRules.evaluate(inputs, thresholds, now)).isEmpty();
    }

    @Test
    void normalVolumeRelativeToBaselineIsNotFlagged() {
        // Same 10/hour baseline as above, but the trailing hour is close to normal.
        BaselineInputs inputs = new BaselineInputs(false, 240, now.minus(Duration.ofDays(30)), 12, 0, 0);

        assertThat(BehaviorBaselineRules.evaluate(inputs, thresholds, now)).isEmpty();
    }
}
