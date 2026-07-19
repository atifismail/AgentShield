package com.agentshield.metrics;

import com.agentshield.common.PolicyDecisionType;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Component;

/**
 * Product-value metrics exposed at {@code /actuator/prometheus} (improvement_plan.md #12) — a
 * thin wrapper around {@link MeterRegistry} so call sites read as intent ("a response was
 * blocked") rather than raw meter names, and the metric names/tags live in exactly one place.
 */
@Component
public class GatewayMetrics {

    private final MeterRegistry registry;

    /** 1 = last scheduled chain verification passed, 0 = it found tampering. Starts optimistic;
     * the first scheduled check (docs/operations.md "Monitoring and alerting") corrects it quickly. */
    private final AtomicInteger auditIntegrityValid = new AtomicInteger(1);

    public GatewayMetrics(MeterRegistry registry) {
        this.registry = registry;
        registry.gauge("agentshield_audit_integrity_valid", auditIntegrityValid);
    }

    public void setAuditIntegrityValid(boolean valid) {
        auditIntegrityValid.set(valid ? 1 : 0);
    }

    public void mcpOAuthTokenRejected() {
        registry.counter("agentshield_mcp_oauth_token_rejected_total").increment();
    }

    public void requestReceived() {
        registry.counter("agentshield_gateway_requests_total").increment();
    }

    /** Also breaks out the DENY/APPROVAL_REQUIRED-specific totals the plan calls for by name. */
    public void decisionRecorded(PolicyDecisionType decision) {
        registry.counter("agentshield_gateway_decisions_total", "decision", decision.name()).increment();
        if (decision == PolicyDecisionType.DENY) {
            registry.counter("agentshield_gateway_denied_total").increment();
        } else if (decision == PolicyDecisionType.APPROVAL_REQUIRED) {
            registry.counter("agentshield_gateway_approval_required_total").increment();
        }
    }

    public void toolDriftDetected() {
        registry.counter("agentshield_tool_drift_detected_total").increment();
    }

    public void responseBlocked() {
        registry.counter("agentshield_response_blocked_total").increment();
    }

    public void incidentCreated() {
        registry.counter("agentshield_incidents_created_total").increment();
    }

    public Timer.Sample startTimer() {
        return Timer.start(registry);
    }

    public void stopGatewayTimer(Timer.Sample sample) {
        sample.stop(registry.timer("agentshield_gateway_latency_seconds"));
    }

    public void stopPolicyEvaluationTimer(Timer.Sample sample) {
        sample.stop(registry.timer("agentshield_policy_evaluation_latency_seconds"));
    }

    public void stopToolForwardTimer(Timer.Sample sample) {
        sample.stop(registry.timer("agentshield_tool_forward_latency_seconds"));
    }
}
