package com.agentshield.risk;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.ActionCategory;
import com.agentshield.common.RiskLevel;
import org.junit.jupiter.api.Test;

class RiskScorerTest {

    private final RiskScorer scorer = new RiskScorer();

    @Test
    void baseScoresMatchActionCategory() {
        assertThat(scorer.score(RiskInput.builder(ActionCategory.READ).build()).score()).isEqualTo(10);
        assertThat(scorer.score(RiskInput.builder(ActionCategory.WRITE).build()).score()).isEqualTo(40);
        assertThat(scorer.score(RiskInput.builder(ActionCategory.DESTRUCTIVE).build()).score()).isEqualTo(70);
        assertThat(scorer.score(RiskInput.builder(ActionCategory.CREDENTIAL_ACCESS).build()).score()).isEqualTo(90);
        assertThat(scorer.score(RiskInput.builder(ActionCategory.EXTERNAL_TRANSFER).build()).score()).isEqualTo(80);
    }

    @Test
    void modifiersStackAdditively() {
        var assessment = scorer.score(RiskInput.builder(ActionCategory.READ)
                .prodEnvironment(true)
                .toolNotApproved(true)
                .schemaDrift(true)
                .secretDetected(true)
                .promptInjectionDetected(true)
                .firstTimeAgentToolPair(true)
                .build());
        // 10 base + 20 + 50 + 50 + 40 + 40 + 10 = 220
        assertThat(assessment.score()).isEqualTo(220);
        assertThat(assessment.level()).isEqualTo(RiskLevel.CRITICAL);
    }

    @Test
    void approvalGrantedReducesScoreButNotBelowZero() {
        var assessment = scorer.score(RiskInput.builder(ActionCategory.READ).approvalGranted(true).build());
        assertThat(assessment.score()).isEqualTo(0);
    }

    @Test
    void riskLevelBoundariesMatchSpec() {
        assertThat(RiskLevel.fromScore(0)).isEqualTo(RiskLevel.LOW);
        assertThat(RiskLevel.fromScore(29)).isEqualTo(RiskLevel.LOW);
        assertThat(RiskLevel.fromScore(30)).isEqualTo(RiskLevel.MEDIUM);
        assertThat(RiskLevel.fromScore(59)).isEqualTo(RiskLevel.MEDIUM);
        assertThat(RiskLevel.fromScore(60)).isEqualTo(RiskLevel.HIGH);
        assertThat(RiskLevel.fromScore(89)).isEqualTo(RiskLevel.HIGH);
        assertThat(RiskLevel.fromScore(90)).isEqualTo(RiskLevel.CRITICAL);
    }
}
