package com.agentshield.dlp;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface DlpFindingRepository extends JpaRepository<DlpFinding, Long>, JpaSpecificationExecutor<DlpFinding> {

    Page<DlpFinding> findByCorrelationIdOrderByCreatedAtAsc(String correlationId, Pageable pageable);
}
