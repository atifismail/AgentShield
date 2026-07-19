package com.agentshield.incident;

import com.agentshield.common.AuditSeverity;
import com.agentshield.common.IncidentStatus;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.metrics.GatewayMetrics;
import java.time.Instant;
import org.springframework.stereotype.Service;

/** Creates an incident record whenever a CRITICAL-severity finding needs security-team attention. */
@Service
public class IncidentService {

    private final IncidentRepository repository;
    private final GatewayMetrics metrics;

    public IncidentService(IncidentRepository repository, GatewayMetrics metrics) {
        this.repository = repository;
        this.metrics = metrics;
    }

    public Incident createFromFinding(String title, String summary, Long relatedAuditEventId,
            Long relatedGatewayRequestId) {
        return create(title, AuditSeverity.CRITICAL, summary, relatedAuditEventId, relatedGatewayRequestId);
    }

    /** Lower-severity counterpart for unusual-but-allowed behavior, not a confirmed policy violation. */
    public Incident createWarning(String title, String summary, Long relatedAuditEventId, Long relatedGatewayRequestId) {
        return create(title, AuditSeverity.WARNING, summary, relatedAuditEventId, relatedGatewayRequestId);
    }

    private Incident create(String title, AuditSeverity severity, String summary, Long relatedAuditEventId,
            Long relatedGatewayRequestId) {
        Incident incident = new Incident();
        incident.setTitle(title);
        incident.setSeverity(severity);
        incident.setStatus(IncidentStatus.OPEN);
        incident.setSummary(summary);
        incident.setRelatedAuditEventId(relatedAuditEventId);
        incident.setRelatedGatewayRequestId(relatedGatewayRequestId);
        incident = repository.save(incident);
        metrics.incidentCreated();
        return incident;
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
