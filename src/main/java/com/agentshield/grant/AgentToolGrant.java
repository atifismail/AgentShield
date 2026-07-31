package com.agentshield.grant;

import com.agentshield.common.ActionCategory;
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

/**
 * An explicit, expiring grant that lets one agent invoke one tool, optionally narrowed further by
 * action category, target environment, resource path pattern, and/or required token scope.
 * Immutable identity/agent/tool; every other field may only ever narrow — see
 * {@link AgentToolGrantService} for creation validation and {@link GrantEvaluationService} for
 * how a grant is matched at gateway time.
 */
@Entity
@Table(name = "agent_tool_grants")
@Getter
@Setter
@NoArgsConstructor
public class AgentToolGrant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "agent_id", nullable = false)
    private Long agentId;

    @Column(name = "tool_id", nullable = false)
    private Long toolId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private GrantStatus status = GrantStatus.ACTIVE;

    /** Null means "not restricted by action category". */
    @Enumerated(EnumType.STRING)
    @Column(name = "action_category", length = 32)
    private ActionCategory actionCategory;

    /** Null means "not restricted by target environment". */
    @Column(name = "target_environment", length = 64)
    private String targetEnvironment;

    /** Null means "not restricted by resource path". Validated grammar — see ResourcePathPatternValidator. */
    @Column(name = "resource_path_pattern", length = 512)
    private String resourcePathPattern;

    /** Null means "not restricted by token scope". Exact membership match, never substring. */
    @Column(name = "required_token_scope", length = 256)
    private String requiredTokenScope;

    @Column(name = "not_before")
    private Instant notBefore;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "revoked_by")
    private String revokedBy;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(length = 2000)
    private String reason;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public boolean isWithinTimeWindow(Instant now) {
        if (notBefore != null && now.isBefore(notBefore)) {
            return false;
        }
        return expiresAt == null || !now.isAfter(expiresAt);
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
