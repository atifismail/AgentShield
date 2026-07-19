package com.agentshield.incident;

import com.agentshield.common.IncidentStatus;
import com.agentshield.common.ResourceNotFoundException;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/incidents")
@Tag(name = "Incidents", description = "Records created from critical detector findings (secret leak, prompt injection, blocked destructive action) with an investigation workflow.")
public class IncidentController {

    private final IncidentRepository repository;
    private final IncidentService incidentService;

    public IncidentController(IncidentRepository repository, IncidentService incidentService) {
        this.repository = repository;
        this.incidentService = incidentService;
    }

    @GetMapping
    public Page<Incident> list(@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
        return repository.findAllByOrderByCreatedAtDesc(PageRequest.of(page, size));
    }

    @GetMapping("/{id}")
    public Incident get(@PathVariable Long id) {
        return repository.findById(id).orElseThrow(() -> new ResourceNotFoundException("incident " + id + " not found"));
    }

    @PatchMapping("/{id}/status")
    public Incident updateStatus(@PathVariable Long id, @Valid @RequestBody StatusUpdateRequest request) {
        return incidentService.updateStatus(id, request.status());
    }

    public record StatusUpdateRequest(@NotNull IncidentStatus status) {
    }
}
