package com.agentshield.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.PolicyDecisionType;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

class GatewayMetricsTest {

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final GatewayMetrics metrics = new GatewayMetrics(registry);

    @Test
    void requestReceivedIncrementsCounter() {
        metrics.requestReceived();
        metrics.requestReceived();

        assertThat(registry.counter("agentshield_gateway_requests_total").count()).isEqualTo(2.0);
    }

    @Test
    void decisionRecordedTagsByDecisionAndBreaksOutDenyAndApprovalRequired() {
        metrics.decisionRecorded(PolicyDecisionType.DENY);
        metrics.decisionRecorded(PolicyDecisionType.APPROVAL_REQUIRED);
        metrics.decisionRecorded(PolicyDecisionType.ALLOW);

        assertThat(registry.counter("agentshield_gateway_decisions_total", "decision", "DENY").count()).isEqualTo(1.0);
        assertThat(registry.counter("agentshield_gateway_decisions_total", "decision", "ALLOW").count()).isEqualTo(1.0);
        assertThat(registry.counter("agentshield_gateway_denied_total").count()).isEqualTo(1.0);
        assertThat(registry.counter("agentshield_gateway_approval_required_total").count()).isEqualTo(1.0);
    }

    @Test
    void timerRecordsAnElapsedSample() {
        var sample = metrics.startTimer();
        metrics.stopGatewayTimer(sample);

        assertThat(registry.timer("agentshield_gateway_latency_seconds").count()).isEqualTo(1);
    }

    @Test
    void driftAndBlockedAndIncidentCountersIncrement() {
        metrics.toolDriftDetected();
        metrics.responseBlocked();
        metrics.incidentCreated();

        assertThat(registry.counter("agentshield_tool_drift_detected_total").count()).isEqualTo(1.0);
        assertThat(registry.counter("agentshield_response_blocked_total").count()).isEqualTo(1.0);
        assertThat(registry.counter("agentshield_incidents_created_total").count()).isEqualTo(1.0);
    }
}
