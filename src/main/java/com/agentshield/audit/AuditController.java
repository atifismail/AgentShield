package com.agentshield.audit;

import com.agentshield.common.AuditSeverity;
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
public class AuditController {

    private final AuditEventRepository repository;

    public AuditController(AuditEventRepository repository) {
        this.repository = repository;
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
}
