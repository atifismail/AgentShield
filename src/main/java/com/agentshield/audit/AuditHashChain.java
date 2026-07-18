package com.agentshield.audit;

import com.agentshield.common.TokenHasher;
import java.time.temporal.ChronoUnit;

/** Canonical content + hash computation shared by AuditService (writes) and AuditIntegrityService (verification). */
final class AuditHashChain {

    static final String ALGORITHM = "SHA-256";
    static final String GENESIS = "GENESIS";

    private AuditHashChain() {
    }

    static String computeHash(AuditEvent event, String previousHash) {
        // Truncated to whole seconds because MariaDB's default TIMESTAMP column (no explicit
        // fractional-seconds precision) silently drops anything finer on write. Verification
        // re-reads the row from the database, so hashing at a precision the column can't
        // actually preserve would make every freshly-written chain "fail" on the very next
        // read — this keeps write-time and read-time hashing agree regardless of DB precision.
        String createdAt = event.getCreatedAt() == null ? "" : event.getCreatedAt().truncatedTo(ChronoUnit.SECONDS).toString();
        String canonical = String.join("|",
                nullSafe(event.getCorrelationId()),
                nullSafe(event.getEventType()),
                event.getActorType() == null ? "" : event.getActorType().name(),
                nullSafe(event.getActorId()),
                event.getAgentId() == null ? "" : event.getAgentId().toString(),
                event.getToolId() == null ? "" : event.getToolId().toString(),
                event.getSeverity() == null ? "" : event.getSeverity().name(),
                nullSafe(event.getMessage()),
                nullSafe(event.getMetadataJson()),
                createdAt,
                previousHash);
        return TokenHasher.sha256Hex(canonical);
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }
}
