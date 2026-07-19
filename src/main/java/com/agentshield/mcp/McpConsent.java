package com.agentshield.mcp;

import com.agentshield.agent.Agent;
import com.agentshield.common.ActionCategory;
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

/**
 * Explicit, human-granted permission for one {@link Agent} (the MCP "client," in MCP terms — see
 * design-mcp-authorization.md §3 for why this reuses Agent rather than a new identity) to use one
 * {@link McpServer}, optionally scoped further to a specific tool and/or action category. This is
 * the direct confused-deputy fix: a tool being APPROVED in the tool registry is no longer
 * sufficient on its own for an MCP-backed tool — the calling agent must also have an ACTIVE,
 * unexpired grant that matches, checked by {@code PolicyEngine} before every call
 * (improvement_plan.md P1, "MCP Authorization And Confused-Deputy Controls Are Missing").
 *
 * {@code toolName}/{@code actionCategory} being independently nullable gives four grant shapes
 * without extra tables: whole-server, server+tool, server+category, server+tool+category. Null
 * means "any" — the same convention {@link com.agentshield.policy.PolicyOverride} already uses.
 */
@Entity
@Table(name = "mcp_consents")
@Getter
@Setter
@NoArgsConstructor
public class McpConsent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "agent_id", nullable = false)
    private Agent agent;

    @ManyToOne(optional = false)
    @JoinColumn(name = "mcp_server_id", nullable = false)
    private McpServer mcpServer;

    /** The MCP tool's own name (not the qualified `serverName:toolName` used in the Tool registry). Null = any tool. */
    @Column(name = "tool_name")
    private String toolName;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_category", length = 32)
    private ActionCategory actionCategory;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private ConsentStatus status = ConsentStatus.ACTIVE;

    @Column(name = "granted_by", nullable = false)
    private String grantedBy;

    @Column(name = "granted_at", nullable = false)
    private Instant grantedAt = Instant.now();

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked_by")
    private String revokedBy;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    public boolean isActive(Instant now) {
        if (status != ConsentStatus.ACTIVE) {
            return false;
        }
        return expiresAt == null || now.isBefore(expiresAt);
    }
}
