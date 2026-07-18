package com.agentshield.risk;

import com.agentshield.common.ActionCategory;

/**
 * Facts the risk engine scores a request against. Booleans default to "no penalty" so callers
 * only need to set the flags that apply to their evaluation phase (pre-call vs. post-response).
 * Detector findings carry a {@link Confidence} (null = not detected) so the risk score reflects
 * how sure the detector was, not just whether it fired at all.
 */
public record RiskInput(
        ActionCategory actionCategory,
        boolean prodEnvironment,
        boolean toolNotApproved,
        boolean schemaDrift,
        Confidence secretConfidence,
        Confidence injectionConfidence,
        boolean firstTimeAgentToolPair,
        boolean approvalGranted
) {

    public static Builder builder(ActionCategory actionCategory) {
        return new Builder(actionCategory);
    }

    public static final class Builder {
        private final ActionCategory actionCategory;
        private boolean prodEnvironment;
        private boolean toolNotApproved;
        private boolean schemaDrift;
        private Confidence secretConfidence;
        private Confidence injectionConfidence;
        private boolean firstTimeAgentToolPair;
        private boolean approvalGranted;

        private Builder(ActionCategory actionCategory) {
            this.actionCategory = actionCategory;
        }

        public Builder prodEnvironment(boolean v) {
            this.prodEnvironment = v;
            return this;
        }

        public Builder toolNotApproved(boolean v) {
            this.toolNotApproved = v;
            return this;
        }

        public Builder schemaDrift(boolean v) {
            this.schemaDrift = v;
            return this;
        }

        /** Convenience for callers that only know "detected or not" — maps true to HIGH confidence. */
        public Builder secretDetected(boolean v) {
            this.secretConfidence = v ? Confidence.HIGH : null;
            return this;
        }

        public Builder secretConfidence(Confidence v) {
            this.secretConfidence = v;
            return this;
        }

        /** Convenience for callers that only know "detected or not" — maps true to HIGH confidence. */
        public Builder promptInjectionDetected(boolean v) {
            this.injectionConfidence = v ? Confidence.HIGH : null;
            return this;
        }

        public Builder injectionConfidence(Confidence v) {
            this.injectionConfidence = v;
            return this;
        }

        public Builder firstTimeAgentToolPair(boolean v) {
            this.firstTimeAgentToolPair = v;
            return this;
        }

        public Builder approvalGranted(boolean v) {
            this.approvalGranted = v;
            return this;
        }

        public RiskInput build() {
            return new RiskInput(actionCategory, prodEnvironment, toolNotApproved, schemaDrift,
                    secretConfidence, injectionConfidence, firstTimeAgentToolPair, approvalGranted);
        }
    }
}
