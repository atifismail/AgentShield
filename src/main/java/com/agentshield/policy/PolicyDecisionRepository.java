package com.agentshield.policy;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PolicyDecisionRepository extends JpaRepository<PolicyDecision, Long> {

    long countByDecisionAndCreatedAtAfter(com.agentshield.common.PolicyDecisionType decision, Instant since);

    Optional<PolicyDecision> findTopByGatewayRequestIdOrderByCreatedAtDesc(Long gatewayRequestId);

    /** Used by the dashboard to bucket recent decisions into a chart — no other consumers. */
    List<PolicyDecision> findByCreatedAtAfterOrderByCreatedAtAsc(Instant since);

    List<PolicyDecision> findByDecisionAndCreatedAtBetweenOrderByCreatedAtDesc(
            com.agentshield.common.PolicyDecisionType decision, Instant from, Instant to);
}
