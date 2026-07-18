package com.agentshield.audit;

import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ResourceNotFoundException;
import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuditPageController {

    private final AuditEventRepository repository;

    public AuditPageController(AuditEventRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/audit")
    public String list(
            @RequestParam(required = false) Long agentId,
            @RequestParam(required = false) Long toolId,
            @RequestParam(required = false) AuditSeverity severity,
            @RequestParam(required = false) Instant since,
            @RequestParam(defaultValue = "0") int page,
            Model model) {
        Page<AuditEvent> events = repository.findAll(AuditSpecifications.search(agentId, toolId, severity, since),
                PageRequest.of(page, 50, Sort.by(Sort.Direction.DESC, "createdAt")));
        model.addAttribute("pageTitle", "Audit");
        model.addAttribute("eventsPage", events);
        model.addAttribute("severities", AuditSeverity.values());
        model.addAttribute("filterAgentId", agentId);
        model.addAttribute("filterToolId", toolId);
        model.addAttribute("filterSeverity", severity);
        return "audit/index";
    }

    @GetMapping("/audit/correlation/{correlationId}")
    public String timeline(@PathVariable String correlationId, Model model) {
        Page<AuditEvent> events = repository.findByCorrelationIdOrderByCreatedAtAsc(correlationId, PageRequest.of(0, 500));
        if (events.isEmpty()) {
            throw new ResourceNotFoundException("no audit events found for correlation " + correlationId);
        }
        model.addAttribute("pageTitle", "Audit timeline");
        model.addAttribute("correlationId", correlationId);
        model.addAttribute("events", events.getContent());
        return "audit/timeline";
    }
}
