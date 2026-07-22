package com.agentshield.codetrust;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AiCodeReceiptRepository extends JpaRepository<AiCodeReceipt, Long> {

    Optional<AiCodeReceipt> findByAssessmentId(Long assessmentId);
}
