package com.agentshield.agent;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.TokenHasher;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Full credential lifecycle for agent authentication tokens (improvement_plan.md #3):
 * create, rotate, revoke, expire, and list — replacing the single long-lived
 * {@code agents.api_key_hash} field. Plaintext tokens are returned exactly once, at creation.
 */
@Service
public class AgentCredentialService {

    private final AgentRepository agentRepository;
    private final AgentCredentialRepository credentialRepository;
    private final AuditService auditService;

    public AgentCredentialService(AgentRepository agentRepository, AgentCredentialRepository credentialRepository,
            AuditService auditService) {
        this.agentRepository = agentRepository;
        this.credentialRepository = credentialRepository;
        this.auditService = auditService;
    }

    public List<AgentCredential> listForAgent(Long agentId) {
        return credentialRepository.findByAgentIdOrderByCreatedAtDesc(agentId);
    }

    /** Returns the new plaintext token — this is the only time it is ever available. */
    @Transactional
    public IssuedToken create(Long agentId, String createdBy, Duration validFor) {
        Agent agent = agentRepository.findById(agentId)
                .orElseThrow(() -> new ResourceNotFoundException("agent " + agentId + " not found"));

        String plaintext = TokenHasher.generateToken();
        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintext));
        credential.setTokenPrefix(plaintext.substring(0, Math.min(8, plaintext.length())));
        credential.setStatus(CredentialStatus.ACTIVE);
        credential.setCreatedBy(createdBy);
        if (validFor != null) {
            credential.setExpiresAt(Instant.now().plus(validFor));
        }
        credential = credentialRepository.save(credential);

        auditService.record(null, "agent.credential_created", ActorType.USER, createdBy, agent.getId(), null,
                AuditSeverity.WARNING,
                "credential " + credential.getId() + " (prefix " + credential.getTokenPrefix()
                        + ") created for agent '" + agent.getName() + "'",
                null);
        return new IssuedToken(credential.getId(), plaintext);
    }

    /** Revokes every currently-active credential for the agent and issues a fresh one. */
    @Transactional
    public IssuedToken rotate(Long agentId, String actor) {
        for (AgentCredential credential : credentialRepository.findByAgentIdOrderByCreatedAtDesc(agentId)) {
            if (credential.getStatus() == CredentialStatus.ACTIVE) {
                revokeInternal(credential, actor);
            }
        }
        return create(agentId, actor, null);
    }

    @Transactional
    public void revoke(Long credentialId, String actor) {
        AgentCredential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> new ResourceNotFoundException("credential " + credentialId + " not found"));
        revokeInternal(credential, actor);
    }

    private void revokeInternal(AgentCredential credential, String actor) {
        credential.setStatus(CredentialStatus.REVOKED);
        credential.setRevokedBy(actor);
        credential.setRevokedAt(Instant.now());
        auditService.record(null, "agent.credential_revoked", ActorType.USER, actor,
                credential.getAgent().getId(), null, AuditSeverity.WARNING,
                "credential " + credential.getId() + " (prefix " + credential.getTokenPrefix() + ") revoked", null);
    }

    /** Runs every minute; ACTIVE credentials past their expiresAt are marked EXPIRED. */
    @Scheduled(fixedDelayString = "PT1M")
    @Transactional
    public void expireOverdueCredentials() {
        Instant now = Instant.now();
        for (AgentCredential credential : credentialRepository.findByStatus(CredentialStatus.ACTIVE)) {
            if (credential.getExpiresAt() != null && now.isAfter(credential.getExpiresAt())) {
                credential.setStatus(CredentialStatus.EXPIRED);
                auditService.record(null, "agent.credential_expired", ActorType.SYSTEM, "scheduler",
                        credential.getAgent().getId(), null, AuditSeverity.INFO,
                        "credential " + credential.getId() + " (prefix " + credential.getTokenPrefix()
                                + ") expired",
                        null);
            }
        }
    }

    public record IssuedToken(Long credentialId, String plaintextToken) {
    }
}
