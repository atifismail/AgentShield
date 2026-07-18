package com.agentshield.audit;

import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Every gateway request must produce at least one audit event (AGENTS.md rule 8).
 * Callers are responsible for never passing raw secret values in {@code metadata} —
 * this service does not attempt to redact, it only persists what it is given
 * (AGENTS.md rule 9: no raw secrets in audit logs).
 */
@Service
public class AuditService {

    private final AuditEventRepository repository;
    private final ObjectMapper objectMapper;

    public AuditService(AuditEventRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    public AuditEvent record(String correlationId, String eventType, ActorType actorType, String actorId,
            Long agentId, Long toolId, AuditSeverity severity, String message, Map<String, Object> metadata) {
        AuditEvent event = new AuditEvent();
        event.setCorrelationId(correlationId);
        event.setEventType(eventType);
        event.setActorType(actorType);
        event.setActorId(actorId);
        event.setAgentId(agentId);
        event.setToolId(toolId);
        event.setSeverity(severity);
        event.setMessage(message);
        event.setMetadataJson(toJson(metadata));
        return repository.save(event);
    }

    private String toJson(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            return "{\"error\":\"failed to serialize audit metadata\"}";
        }
    }
}
