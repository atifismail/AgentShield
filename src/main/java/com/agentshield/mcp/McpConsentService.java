package com.agentshield.mcp;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentRepository;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.mcp.McpConsentDtos.CreateConsentRequest;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The direct confused-deputy fix (design-mcp-authorization.md §5): a tool being APPROVED is not
 * sufficient on its own for an MCP-backed tool — the calling agent also needs an ACTIVE,
 * unexpired {@link McpConsent} grant. {@link com.agentshield.policy.PolicyEngine} calls
 * {@link #hasActiveConsent} as a fixed pre-call rule; this service owns the grant lifecycle
 * (create/revoke/expire) and its audit trail.
 */
@Service
public class McpConsentService {

    private final McpConsentRepository consentRepository;
    private final AgentRepository agentRepository;
    private final McpServerRepository mcpServerRepository;
    private final AuditService auditService;

    public McpConsentService(McpConsentRepository consentRepository, AgentRepository agentRepository,
            McpServerRepository mcpServerRepository, AuditService auditService) {
        this.consentRepository = consentRepository;
        this.agentRepository = agentRepository;
        this.mcpServerRepository = mcpServerRepository;
        this.auditService = auditService;
    }

    /**
     * Used by {@code PolicyEngine} on the hot path — no dedicated audit write here. A denial is
     * already fully captured by the standard {@code gateway.denied}/{@code gateway.policy_decision}
     * audit events {@code GatewayService} writes for every DENY, correlation-id-linked to the
     * request (which this method, called mid-evaluation, doesn't have) — a second, uncorrelated
     * {@code mcp.consent_denied} event would just be a duplicate, not additional coverage.
     */
    public boolean hasActiveConsent(Long agentId, Long mcpServerId, String toolName,
            com.agentshield.common.ActionCategory actionCategory) {
        return !consentRepository.findMatching(agentId, mcpServerId, toolName, actionCategory, Instant.now())
                .isEmpty();
    }

    @Transactional
    public McpConsent create(CreateConsentRequest request, String grantedBy) {
        Agent agent = agentRepository.findById(request.agentId())
                .orElseThrow(() -> new ResourceNotFoundException("agent " + request.agentId() + " not found"));
        McpServer mcpServer = mcpServerRepository.findById(request.mcpServerId())
                .orElseThrow(() -> new ResourceNotFoundException("MCP server " + request.mcpServerId() + " not found"));

        McpConsent consent = new McpConsent();
        consent.setAgent(agent);
        consent.setMcpServer(mcpServer);
        consent.setToolName(request.toolName());
        consent.setActionCategory(request.actionCategory());
        consent.setStatus(ConsentStatus.ACTIVE);
        consent.setGrantedBy(grantedBy);
        consent.setExpiresAt(request.expiresAt());
        consent = consentRepository.save(consent);

        auditService.record(null, "mcp.consent_granted", ActorType.USER, grantedBy, agent.getId(), null,
                AuditSeverity.INFO,
                "MCP consent granted: agent '" + agent.getName() + "' -> server '" + mcpServer.getName() + "'"
                        + (request.toolName() != null ? ", tool=" + request.toolName() : "")
                        + (request.actionCategory() != null ? ", actionCategory=" + request.actionCategory() : ""),
                null);
        return consent;
    }

    @Transactional
    public McpConsent revoke(Long id, String revokedBy) {
        McpConsent consent = consentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("MCP consent " + id + " not found"));
        consent.setStatus(ConsentStatus.REVOKED);
        consent.setRevokedBy(revokedBy);
        consent.setRevokedAt(Instant.now());

        auditService.record(null, "mcp.consent_revoked", ActorType.USER, revokedBy, consent.getAgent().getId(), null,
                AuditSeverity.WARNING,
                "MCP consent " + id + " revoked: agent '" + consent.getAgent().getName() + "' -> server '"
                        + consent.getMcpServer().getName() + "'",
                null);
        return consent;
    }

    public List<McpConsent> listAll() {
        return consentRepository.findAllByOrderByGrantedAtDesc();
    }

    public List<McpConsent> listForAgent(Long agentId) {
        return consentRepository.findByAgentIdOrderByGrantedAtDesc(agentId);
    }

    public List<McpConsent> listForServer(Long mcpServerId) {
        return consentRepository.findByMcpServerIdOrderByGrantedAtDesc(mcpServerId);
    }

    /** Same sweep pattern as {@code ApprovalService.expireOverdueApprovals()}. */
    @org.springframework.scheduling.annotation.Scheduled(fixedDelayString = "PT1M")
    @Transactional
    public void expireOverdueConsents() {
        Instant now = Instant.now();
        for (McpConsent consent : consentRepository.findByStatus(ConsentStatus.ACTIVE)) {
            if (consent.getExpiresAt() != null && !now.isBefore(consent.getExpiresAt())) {
                consent.setStatus(ConsentStatus.EXPIRED);
                auditService.record(null, "mcp.consent_expired", ActorType.SYSTEM, "scheduler",
                        consent.getAgent().getId(), null, AuditSeverity.INFO,
                        "MCP consent " + consent.getId() + " expired: agent '" + consent.getAgent().getName()
                                + "' -> server '" + consent.getMcpServer().getName() + "'",
                        null);
            }
        }
    }
}
