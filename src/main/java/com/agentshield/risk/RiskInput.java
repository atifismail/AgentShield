package com.agentshield.risk;

import com.agentshield.common.ActionCategory;

/**
 * Facts the risk engine scores a request against. Booleans default to "no penalty" so callers
 * only need to set the flags that apply to their evaluation phase (pre-call vs. post-response).
 */
public record RiskInput(
        ActionCategory actionCategory,
        boolean prodEnvironment,
        boolean toolNotApproved,
        boolean schemaDrift,
        boolean secretDetected,
        boolean promptInjectionDetected,
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
        private boolean secretDetected;
        private boolean promptInjectionDetected;
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

        public Builder secretDetected(boolean v) {
            this.secretDetected = v;
            return this;
        }

        public Builder promptInjectionDetected(boolean v) {
            this.promptInjectionDetected = v;
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
                    secretDetected, promptInjectionDetected, firstTimeAgentToolPair, approvalGranted);
        }
    }
}
