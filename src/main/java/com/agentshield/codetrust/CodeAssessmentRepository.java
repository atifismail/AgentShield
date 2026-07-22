package com.agentshield.codetrust;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

public interface CodeAssessmentRepository extends JpaRepository<CodeAssessment, Long> {

    List<CodeAssessment> findByRepoAndBranchOrderByCreatedAtDesc(String repo, String branch);

    List<CodeAssessment> findAllByOrderByCreatedAtDesc();

    /**
     * Row-level lock held for the rest of the caller's transaction — same pattern as
     * {@code ApprovalRequestRepository.findByIdForUpdate}, so two concurrent review decisions on
     * the same blocked assessment can't both observe BLOCKED and both issue a receipt.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from CodeAssessment a where a.id = :id")
    Optional<CodeAssessment> findByIdForUpdate(Long id);
}
