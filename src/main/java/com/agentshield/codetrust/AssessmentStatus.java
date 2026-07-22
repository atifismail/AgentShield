package com.agentshield.codetrust;

/**
 * Lifecycle of a {@link CodeAssessment}. PENDING is the initial/re-scan-required state; a
 * submission is evaluated immediately into either PASSED (no blocking finding, or a human
 * approved past one) or BLOCKED (a CRITICAL/HIGH finding exists and no approval has been granted
 * yet). BLOCKED is not necessarily terminal — see {@code CodeAssessmentService.approve}.
 */
public enum AssessmentStatus {
    PENDING,
    PASSED,
    BLOCKED
}
