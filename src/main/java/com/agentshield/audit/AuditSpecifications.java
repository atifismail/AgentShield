package com.agentshield.audit;

import com.agentshield.common.AuditSeverity;
import java.time.Instant;
import org.springframework.data.jpa.domain.Specification;

/**
 * Built as a Specification (rather than a single JPQL query with "(:param is null or ...)"
 * clauses) because that pattern hits a PostgreSQL prepared-statement parameter-type-inference
 * error for some column types — a Specification only adds a predicate when the value is
 * actually present, so no ambiguous "? is null" comparison is ever sent to the database.
 */
final class AuditSpecifications {

    private AuditSpecifications() {
    }

    static Specification<AuditEvent> search(Long agentId, Long toolId, AuditSeverity severity, Instant since) {
        Specification<AuditEvent> spec = Specification.where(null);
        if (agentId != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("agentId"), agentId));
        }
        if (toolId != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("toolId"), toolId));
        }
        if (severity != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("severity"), severity));
        }
        if (since != null) {
            spec = spec.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("createdAt"), since));
        }
        return spec;
    }
}
