package com.agentshield.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long>, JpaSpecificationExecutor<AuditEvent> {

    Page<AuditEvent> findByCorrelationIdOrderByCreatedAtAsc(String correlationId, Pageable pageable);

    Page<AuditEvent> findAllByOrderByCreatedAtDesc(Pageable pageable);
}
