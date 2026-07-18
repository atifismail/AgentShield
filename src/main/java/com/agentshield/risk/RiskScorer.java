package com.agentshield.risk;

import com.agentshield.common.RiskLevel;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Deterministic risk scoring per PROJECT_PLAN.md section 11. No model or paid API is involved:
 * a fixed base score by action category, plus fixed additive/subtractive modifiers.
 */
@Component
public class RiskScorer {

    public RiskAssessment score(RiskInput input) {
        List<String> reasons = new ArrayList<>();
        int score = baseScore(input, reasons);

        if (input.prodEnvironment()) {
            score += 20;
            reasons.add("target environment is PROD (+20)");
        }
        if (input.toolNotApproved()) {
            score += 50;
            reasons.add("tool is not approved (+50)");
        }
        if (input.schemaDrift()) {
            score += 50;
            reasons.add("tool schema/description drift detected (+50)");
        }
        if (input.secretConfidence() != null) {
            int add = scoreFor(input.secretConfidence());
            score += add;
            reasons.add("secret-like value detected in response, confidence=" + input.secretConfidence() + " (+" + add + ")");
        }
        if (input.injectionConfidence() != null) {
            int add = scoreFor(input.injectionConfidence());
            score += add;
            reasons.add("prompt-injection pattern detected in response, confidence=" + input.injectionConfidence() + " (+" + add + ")");
        }
        if (input.firstTimeAgentToolPair()) {
            score += 10;
            reasons.add("first time this agent/tool pair has been seen (+10)");
        }
        if (input.approvalGranted()) {
            score -= 30;
            reasons.add("human approval already granted (-30)");
        }

        score = Math.max(0, score);
        return new RiskAssessment(score, RiskLevel.fromScore(score), reasons);
    }

    private int baseScore(RiskInput input, List<String> reasons) {
        int base = switch (input.actionCategory()) {
            case READ -> 10;
            case WRITE -> 40;
            case DESTRUCTIVE -> 70;
            case CREDENTIAL_ACCESS -> 90;
            case EXTERNAL_TRANSFER -> 80;
        };
        reasons.add("base score for " + input.actionCategory() + " (" + base + ")");
        return base;
    }

    private int scoreFor(Confidence confidence) {
        return switch (confidence) {
            case HIGH -> 40;
            case MEDIUM -> 25;
            case LOW -> 10;
        };
    }
}
