package com.agentshield.dlp;

import com.agentshield.risk.DetectorCategory;
import java.time.Instant;
import org.springframework.data.jpa.domain.Specification;

/**
 * Built as a {@link Specification} rather than a single JPQL query with "(:param is null or ...)"
 * clauses — see {@code com.agentshield.audit.AuditSpecifications} for why: that pattern hits a
 * PostgreSQL prepared-statement parameter-type-inference error for some column types.
 */
final class DlpFindingSpecifications {

    private DlpFindingSpecifications() {
    }

    static Specification<DlpFinding> search(ContentStage stage, DetectorCategory category, Instant since) {
        Specification<DlpFinding> spec = Specification.where(null);
        if (stage != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("contentStage"), stage));
        }
        if (category != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("category"), category));
        }
        if (since != null) {
            spec = spec.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("createdAt"), since));
        }
        return spec;
    }
}
