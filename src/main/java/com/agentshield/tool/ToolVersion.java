package com.agentshield.tool;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "tool_versions")
@Getter
@Setter
@NoArgsConstructor
public class ToolVersion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tool_id", nullable = false)
    private Tool tool;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "schema_json")
    private String schemaJson;

    @Column(length = 4000)
    private String description;

    @Column(nullable = false, length = 128)
    private String hash;

    @Column(name = "detected_at", nullable = false)
    private Instant detectedAt = Instant.now();

    @Column(name = "approved_by")
    private String approvedBy;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private ToolVersionStatus status = ToolVersionStatus.DETECTED;
}
