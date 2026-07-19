package com.agentshield.audit;

import com.agentshield.audit.AuditIntegrityService.VerificationResult;
import com.agentshield.common.AuditSeverity;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit")
@Tag(name = "Audit", description = "The tamper-evident, hash-chained audit trail every gateway request writes to. Search, correlation timelines, and chain integrity verification.")
public class AuditController {

    private final AuditEventRepository repository;
    private final AuditIntegrityService integrityService;

    public AuditController(AuditEventRepository repository, AuditIntegrityService integrityService) {
        this.repository = repository;
        this.integrityService = integrityService;
    }

    @GetMapping
    public Page<AuditEvent> search(
            @RequestParam(required = false) Long agentId,
            @RequestParam(required = false) Long toolId,
            @RequestParam(required = false) AuditSeverity severity,
            @RequestParam(required = false) Instant since,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return repository.findAll(AuditSpecifications.search(agentId, toolId, severity, since),
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    @GetMapping("/correlation/{correlationId}")
    public Page<AuditEvent> timeline(@PathVariable String correlationId,
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "200") int size) {
        return repository.findByCorrelationIdOrderByCreatedAtAsc(correlationId, PageRequest.of(page, size));
    }

    /** Read-only: recomputes and checks the audit hash chain. Safe to call at any time. */
    @GetMapping("/verify-integrity")
    public VerificationResult verifyIntegrity() {
        return integrityService.verifyChain();
    }
}
