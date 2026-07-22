package com.agentshield.gateway;

import com.agentshield.common.ActionCategory;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GatewayRequestRepository extends JpaRepository<GatewayRequest, Long> {

    Optional<GatewayRequest> findByCorrelationId(String correlationId);

    long countByCreatedAtAfter(Instant since);

    Page<GatewayRequest> findByAgentIdOrderByCreatedAtDesc(Long agentId, Pageable pageable);

    Page<GatewayRequest> findAllByOrderByCreatedAtDesc(Pageable pageable);

    boolean existsByAgentIdAndToolId(Long agentId, Long toolId);

    boolean existsByAgentIdAndToolIdAndActionCategoryAndTargetEnvironment(Long agentId, Long toolId,
            ActionCategory actionCategory, String targetEnvironment);

    long countByAgentIdAndCreatedAtAfter(Long agentId, Instant since);

    long countByAgentId(Long agentId);

    Optional<GatewayRequest> findTopByAgentIdOrderByCreatedAtAsc(Long agentId);

    /** SIEM export range query (improvement_plan.md A5) — the spine {@code SiemEventExportService}
     * builds one flat event per gateway request from. */
    List<GatewayRequest> findByCreatedAtBetweenOrderByCreatedAtAsc(Instant from, Instant to);
}
