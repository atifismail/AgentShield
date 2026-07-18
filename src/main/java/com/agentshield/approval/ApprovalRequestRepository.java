package com.agentshield.approval;

import com.agentshield.common.ApprovalStatus;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApprovalRequestRepository extends JpaRepository<ApprovalRequest, Long> {

    List<ApprovalRequest> findByStatusOrderByCreatedAtAsc(ApprovalStatus status);

    long countByStatus(ApprovalStatus status);

    Optional<ApprovalRequest> findByGatewayRequestId(Long gatewayRequestId);

    List<ApprovalRequest> findAllByOrderByCreatedAtDesc();
}
