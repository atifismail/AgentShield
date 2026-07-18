package com.agentshield.common;

public enum RiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /** Boundaries per PROJECT_PLAN.md section 11: 0-29 LOW, 30-59 MEDIUM, 60-89 HIGH, 90+ CRITICAL. */
    public static RiskLevel fromScore(int score) {
        if (score >= 90) {
            return CRITICAL;
        }
        if (score >= 60) {
            return HIGH;
        }
        if (score >= 30) {
            return MEDIUM;
        }
        return LOW;
    }
}
