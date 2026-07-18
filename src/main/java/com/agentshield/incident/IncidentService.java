package com.agentshield.incident;

import com.agentshield.common.AuditSeverity;
import com.agentshield.common.IncidentStatus;
import com.agentshield.common.ResourceNotFoundException;
import java.time.Instant;
import org.springframework.stereotype.Service;

/** Creates an incident record whenever a CRITICAL-severity finding needs security-team attention. */
@Service
public class IncidentService {

    private final IncidentRepository repository;

    public IncidentService(IncidentRepository repository) {
        this.repository = repository;
    }

    public Incident createFromFinding(String title, String summary, Long relatedAuditEventId,
            Long relatedGatewayRequestId) {
        Incident incident = new Incident();
        incident.setTitle(title);
        incident.setSeverity(AuditSeverity.CRITICAL);
        incident.setStatus(IncidentStatus.OPEN);
        incident.setSummary(summary);
        incident.setRelatedAuditEventId(relatedAuditEventId);
        incident.setRelatedGatewayRequestId(relatedGatewayRequestId);
        return repository.save(incident);
    }

    /** Investigation workflow: OPEN -> ACKNOWLEDGED -> RESOLVED, or OPEN -> FALSE_POSITIVE. */
    public Incident updateStatus(Long id, IncidentStatus newStatus) {
        Incident incident = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("incident " + id + " not found"));
        incident.setStatus(newStatus);
        incident.setUpdatedAt(Instant.now());
        return repository.save(incident);
    }
}
