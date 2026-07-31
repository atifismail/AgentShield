package com.agentshield.approval;

import com.agentshield.common.ActionCategory;
import com.agentshield.security.UserRole;
import com.agentshield.tool.ToolRiskTier;
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
 * Routes an already-{@code APPROVAL_REQUIRED} request to the correct human role
 * (agentshield_policy_evidence_execution_plan_2026-07-30.md work package 3). Every predicate
 * field is optional; a null predicate matches anything. Priority is a plain integer — higher
 * value wins; see {@link ApprovalProfileResolutionService}.
 */
@Entity
@Table(name = "approval_profiles")
@Getter
@Setter
@NoArgsConstructor
public class ApprovalProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private int priority;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(length = 2000)
    private String description;

    /** Null means "not restricted to one agent". */
    @Column(name = "agent_id")
    private Long agentId;

    /** Null means "not restricted to one tool". */
    @Column(name = "tool_id")
    private Long toolId;

    /** Null means "not restricted by tool group". */
    @Column(name = "tool_group", length = 128)
    private String toolGroup;

    /** Null means "not restricted by action category". */
    @Enumerated(EnumType.STRING)
    @Column(name = "action_category", length = 32)
    private ActionCategory actionCategory;

    /** Null means "not restricted by target environment". */
    @Column(name = "target_environment", length = 64)
    private String targetEnvironment;

    /** Null means "not restricted by tool risk tier". */
    @Enumerated(EnumType.STRING)
    @Column(name = "risk_tier", length = 32)
    private ToolRiskTier riskTier;

    @Enumerated(EnumType.STRING)
    @Column(name = "target_role", nullable = false, length = 32)
    private UserRole targetRole;

    /** Null means "use the deployment's default approval expiration". */
    @Column(name = "expiration_minutes")
    private Integer expirationMinutes;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    /** Two profiles are ambiguous if they'd both match the exact same request set at the same priority. */
    public boolean hasSamePredicatesAs(ApprovalProfile other) {
        return java.util.Objects.equals(agentId, other.agentId)
                && java.util.Objects.equals(toolId, other.toolId)
                && java.util.Objects.equals(normalizedToolGroup(), other.normalizedToolGroup())
                && actionCategory == other.actionCategory
                && java.util.Objects.equals(normalizedEnvironment(), other.normalizedEnvironment())
                && riskTier == other.riskTier;
    }

    private String normalizedToolGroup() {
        return toolGroup == null ? null : toolGroup.toLowerCase();
    }

    private String normalizedEnvironment() {
        return targetEnvironment == null ? null : targetEnvironment.toLowerCase();
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
