package com.agentshield.policy;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PolicyDecisionRepository extends JpaRepository<PolicyDecision, Long> {

    long countByDecisionAndCreatedAtAfter(com.agentshield.common.PolicyDecisionType decision, Instant since);

    // Tie-broken by id, not just createdAt: MariaDB's TIMESTAMP column here is second-resolution
    // (no fractional-seconds precision), so two decisions recorded for the same gateway request
    // within the same second — e.g. the pre-call APPROVAL_REQUIRED decision and the post-approval
    // execution's DENY decision — can tie on createdAt. Auto-increment id reflects true insertion
    // order regardless of clock resolution.
    Optional<PolicyDecision> findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc(Long gatewayRequestId);

    /** Used by the dashboard to bucket recent decisions into a chart — no other consumers. */
    List<PolicyDecision> findByCreatedAtAfterOrderByCreatedAtAsc(Instant since);

    List<PolicyDecision> findByDecisionAndCreatedAtBetweenOrderByCreatedAtDesc(
            com.agentshield.common.PolicyDecisionType decision, Instant from, Instant to);

    long countByGatewayRequest_AgentIdAndDecisionAndCreatedAtAfter(Long agentId,
            com.agentshield.common.PolicyDecisionType decision, Instant since);
}
