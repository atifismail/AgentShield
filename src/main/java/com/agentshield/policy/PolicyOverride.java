package com.agentshield.policy;

import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
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
 * A database-backed rule an operator can add without a code change (improvement_plan.md #8).
 * Null fields match anything; a non-null field must match the request exactly (case-insensitive
 * for strings). Only consulted when the fixed {@link PolicyEngine} rules would otherwise ALLOW —
 * see {@link PolicyEngine#evaluateRequest}.
 */
@Entity
@Table(name = "policy_overrides")
@Getter
@Setter
@NoArgsConstructor
public class PolicyOverride {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private boolean enabled = true;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_category", length = 32)
    private ActionCategory actionCategory;

    @Column(name = "target_environment", length = 64)
    private String targetEnvironment;

    @Column(name = "tool_group", length = 128)
    private String toolGroup;

    @Column(name = "agent_name")
    private String agentName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private PolicyDecisionType decision;

    @Column(nullable = false, length = 2000)
    private String reason;

    /** Lower runs first when multiple overrides match. */
    @Column(nullable = false)
    private int priority = 100;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public boolean matches(PolicyEvaluationContext ctx) {
        if (!enabled) {
            return false;
        }
        if (actionCategory != null && actionCategory != ctx.actionCategory()) {
            return false;
        }
        if (targetEnvironment != null && !targetEnvironment.equalsIgnoreCase(ctx.targetEnvironment())) {
            return false;
        }
        if (toolGroup != null && !toolGroup.equalsIgnoreCase(ctx.tool().getToolGroup())) {
            return false;
        }
        if (agentName != null && !agentName.equalsIgnoreCase(ctx.agent().getName())) {
            return false;
        }
        return true;
    }
}
