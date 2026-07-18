package com.agentshield.audit;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long>, JpaSpecificationExecutor<AuditEvent> {

    Page<AuditEvent> findByCorrelationIdOrderByCreatedAtAsc(String correlationId, Pageable pageable);

    Page<AuditEvent> findAllByOrderByCreatedAtDesc(Pageable pageable);

    /**
     * Locks the most recent row so concurrent writers can't both read the same "previous hash"
     * and fork the chain — every insert serializes on this read (AuditService#record).
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<AuditEvent> findFirstByOrderByIdDesc();

    List<AuditEvent> findAllByOrderByIdAsc();
}
