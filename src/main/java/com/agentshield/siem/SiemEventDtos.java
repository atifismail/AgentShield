package com.agentshield.siem;

import java.time.Instant;
import java.util.List;

/**
 * The flat, normalized event schema improvement_plan.md A5 specifies for SIEM/Splunk/Elastic
 * ingest. Deliberately carries only detector category/confidence metadata in {@link #findings()} —
 * never a raw secret/PII value — the same discipline {@code DetectionMatch}/{@code DlpFinding}
 * already enforce.
 */
public final class SiemEventDtos {

    private SiemEventDtos() {
    }

    public record SiemEvent(
            String eventType,
            Instant timestamp,
            Long agentId,
            String toolName,
            String operation,
            String targetResource,
            String decision,
            Integer riskScore,
            List<String> findings,
            String approvalStatus,
            List<String> policyRuleIds,
            String traceId
    ) {
    }
}
