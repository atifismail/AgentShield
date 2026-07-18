package com.agentshield.audit;

import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "audit_events")
@Getter
@Setter
@NoArgsConstructor
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "correlation_id", length = 64)
    private String correlationId;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "actor_type", nullable = false, length = 32)
    private ActorType actorType;

    @Column(name = "actor_id")
    private String actorId;

    @Column(name = "agent_id")
    private Long agentId;

    @Column(name = "tool_id")
    private Long toolId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AuditSeverity severity;

    @Column(nullable = false, length = 4000)
    private String message;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "metadata_json")
    private String metadataJson;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
