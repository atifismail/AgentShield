package com.agentshield.incident;

import com.agentshield.audit.AuditEventRepository;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.gateway.GatewayRequestRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class IncidentPageController {

    private final IncidentRepository incidentRepository;
    private final AuditEventRepository auditEventRepository;
    private final GatewayRequestRepository gatewayRequestRepository;

    public IncidentPageController(IncidentRepository incidentRepository, AuditEventRepository auditEventRepository,
            GatewayRequestRepository gatewayRequestRepository) {
        this.incidentRepository = incidentRepository;
        this.auditEventRepository = auditEventRepository;
        this.gatewayRequestRepository = gatewayRequestRepository;
    }

    @GetMapping("/incidents")
    public String list(Model model) {
        model.addAttribute("pageTitle", "Incidents");
        model.addAttribute("incidentsPage",
                incidentRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(0, 50, Sort.by(Sort.Direction.DESC, "createdAt"))));
        return "incidents/index";
    }

    @GetMapping("/incidents/{id}")
    public String detail(@PathVariable Long id, Model model) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("incident " + id + " not found"));
        model.addAttribute("pageTitle", "Incident: " + incident.getTitle());
        model.addAttribute("incident", incident);
        if (incident.getRelatedAuditEventId() != null) {
            auditEventRepository.findById(incident.getRelatedAuditEventId()).ifPresent(e -> model.addAttribute("auditEvent", e));
        }
        if (incident.getRelatedGatewayRequestId() != null) {
            gatewayRequestRepository.findById(incident.getRelatedGatewayRequestId()).ifPresent(r -> model.addAttribute("gatewayRequest", r));
        }
        return "incidents/detail";
    }
}
