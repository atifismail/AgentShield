package com.agentshield.audit;

import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.metrics.GatewayMetrics;
import java.util.List;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Recomputes the audit hash chain and compares it against what's stored, to detect tampering
 * (improvement_plan.md #4). Rows written before this feature shipped have a null
 * {@code event_hash} — verification treats the first row that has one as a fresh chain start
 * rather than a failure, matching how {@link AuditService} handles that same transition.
 */
@Service
public class AuditIntegrityService {

    private final AuditEventRepository repository;
    private final AuditService auditService;
    private final GatewayMetrics metrics;

    public AuditIntegrityService(AuditEventRepository repository, AuditService auditService, GatewayMetrics metrics) {
        this.repository = repository;
        this.auditService = auditService;
        this.metrics = metrics;
    }

    /**
     * Background check backing the {@code agentshield_audit_integrity_valid} gauge
     * (docs/operations.md "Monitoring and alerting") — the on-demand
     * {@code GET /api/audit/verify-integrity} endpoint stays the authoritative, immediate check;
     * this just means a broken chain gets noticed and alerted on even if nobody happens to click
     * "Verify Integrity" that day. Re-scans the whole chain each run (same cost as the manual
     * endpoint) — fine at this product's scale; if the audit table grows large enough for that to
     * matter, this is the place to add checkpointing.
     */
    @Scheduled(fixedDelayString = "PT30M")
    public void scheduledVerify() {
        VerificationResult result = verifyChain();
        metrics.setAuditIntegrityValid(result.valid());
        if (!result.valid()) {
            auditService.record(null, "audit.integrity_check_failed", ActorType.SYSTEM, "audit-integrity-monitor",
                    null, null, AuditSeverity.CRITICAL,
                    "scheduled audit chain verification found tampering at event " + result.firstBrokenEventId()
                            + ": " + result.reason(),
                    null);
        }
    }

    public VerificationResult verifyChain() {
        List<AuditEvent> events = repository.findAllByOrderByIdAsc();
        String expectedPrevious = AuditHashChain.GENESIS;
        int checked = 0;

        for (AuditEvent event : events) {
            if (event.getEventHash() == null) {
                // Legacy row from before the hash chain existed — skip, and treat the next
                // hashed row as a fresh chain start (mirrors AuditService's write-side behavior).
                expectedPrevious = AuditHashChain.GENESIS;
                continue;
            }
            if (!expectedPrevious.equals(event.getPreviousEventHash())) {
                return VerificationResult.broken(event.getId(), checked, "previous_event_hash does not match the prior row's event_hash");
            }
            String recomputed = AuditHashChain.computeHash(event, event.getPreviousEventHash());
            if (!recomputed.equals(event.getEventHash())) {
                return VerificationResult.broken(event.getId(), checked, "stored event_hash does not match its recomputed content hash");
            }
            expectedPrevious = event.getEventHash();
            checked++;
        }
        return VerificationResult.valid(checked);
    }

    public record VerificationResult(boolean valid, int eventsChecked, Long firstBrokenEventId, String reason) {

        static VerificationResult valid(int eventsChecked) {
            return new VerificationResult(true, eventsChecked, null, null);
        }

        static VerificationResult broken(Long eventId, int eventsCheckedBeforeFailure, String reason) {
            return new VerificationResult(false, eventsCheckedBeforeFailure, eventId, reason);
        }
    }
}
