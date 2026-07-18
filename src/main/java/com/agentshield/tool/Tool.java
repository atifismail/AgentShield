package com.agentshield.tool;

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
@Table(name = "tools")
@Getter
@Setter
@NoArgsConstructor
public class Tool {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 64)
    private ToolType type;

    @Column(name = "tool_group", nullable = false, length = 128)
    private String toolGroup = "default";

    @Column(name = "endpoint_url", length = 1024)
    private String endpointUrl;

    private String owner;

    private String environment;

    @Column(length = 4000)
    private String description;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "schema_json")
    private String schemaJson;

    @Column(name = "approved_hash", length = 128)
    private String approvedHash;

    @Column(name = "current_hash", length = 128)
    private String currentHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "approval_status", nullable = false, length = 32)
    private ToolApprovalStatus approvalStatus = ToolApprovalStatus.PENDING;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public boolean isApproved() {
        return approvalStatus == ToolApprovalStatus.APPROVED;
    }

    public boolean hasDrift() {
        return approvedHash != null && currentHash != null && !approvedHash.equals(currentHash);
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
