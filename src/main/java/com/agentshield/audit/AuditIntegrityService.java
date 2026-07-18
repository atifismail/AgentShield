package com.agentshield.audit;

import java.util.List;
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

    public AuditIntegrityService(AuditEventRepository repository) {
        this.repository = repository;
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
