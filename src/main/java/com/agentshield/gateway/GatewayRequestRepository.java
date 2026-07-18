package com.agentshield.gateway;

import java.time.Instant;
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
}
