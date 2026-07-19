package com.agentshield.approval;

import com.agentshield.common.ApprovalStatus;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

public interface ApprovalRequestRepository extends JpaRepository<ApprovalRequest, Long> {

    List<ApprovalRequest> findByStatusOrderByCreatedAtAsc(ApprovalStatus status);

    long countByStatus(ApprovalStatus status);

    Optional<ApprovalRequest> findByGatewayRequestId(Long gatewayRequestId);

    List<ApprovalRequest> findAllByOrderByCreatedAtDesc();

    /**
     * Row-level lock held for the rest of the caller's transaction — used by approve()/reject()
     * so two concurrent decisions on the same approval can't both observe PENDING and both
     * execute the tool call (improvement_plan.md P1 "Approval Concurrency Needs A Negative
     * Security Test"). The second caller blocks until the first commits, then re-reads the
     * now-decided row and gets a conflict instead of a duplicate execution.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from ApprovalRequest a where a.id = :id")
    Optional<ApprovalRequest> findByIdForUpdate(Long id);
}
