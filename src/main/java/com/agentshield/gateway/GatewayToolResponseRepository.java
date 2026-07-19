package com.agentshield.gateway;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GatewayToolResponseRepository extends JpaRepository<GatewayToolResponse, Long> {

    Optional<GatewayToolResponse> findByGatewayRequestId(Long gatewayRequestId);

    long countByGatewayRequestId(Long gatewayRequestId);
}
