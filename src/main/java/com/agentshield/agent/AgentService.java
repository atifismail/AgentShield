package com.agentshield.agent;

import com.agentshield.agent.AgentDtos.CreateAgentRequest;
import com.agentshield.agent.AgentDtos.UpdateAgentRequest;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.TokenHasher;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AgentService {

    private final AgentRepository repository;
    private final AuditService auditService;

    public AgentService(AgentRepository repository, AuditService auditService) {
        this.repository = repository;
        this.auditService = auditService;
    }

    @Transactional
    public Agent create(CreateAgentRequest request) {
        repository.findByName(request.name()).ifPresent(a -> {
            throw new ConflictException("an agent named '" + request.name() + "' already exists");
        });
        Agent agent = new Agent();
        agent.setName(request.name());
        agent.setDescription(request.description());
        agent.setOwner(request.owner());
        agent.setEnvironment(request.environment());
        agent.setAllowedToolGroups(joinGroups(request.allowedToolGroups()));
        agent = repository.save(agent);
        auditService.record(null, "agent.created", ActorType.USER, agent.getOwner(), agent.getId(), null,
                AuditSeverity.INFO, "agent '" + agent.getName() + "' registered", null);
        return agent;
    }

    public Agent get(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("agent " + id + " not found"));
    }

    public List<Agent> list() {
        return repository.findAll();
    }

    @Transactional
    public Agent update(Long id, UpdateAgentRequest request) {
        Agent agent = get(id);
        if (request.description() != null) {
            agent.setDescription(request.description());
        }
        if (request.owner() != null) {
            agent.setOwner(request.owner());
        }
        if (request.environment() != null) {
            agent.setEnvironment(request.environment());
        }
        if (request.allowedToolGroups() != null) {
            agent.setAllowedToolGroups(joinGroups(request.allowedToolGroups()));
        }
        agent.touch();
        return agent;
    }

    @Transactional
    public Agent setEnabled(Long id, boolean enabled) {
        Agent agent = get(id);
        agent.setStatus(enabled ? AgentStatus.ENABLED : AgentStatus.DISABLED);
        agent.touch();
        auditService.record(null, enabled ? "agent.enabled" : "agent.disabled", ActorType.USER, agent.getOwner(),
                agent.getId(), null, AuditSeverity.WARNING,
                "agent '" + agent.getName() + "' " + (enabled ? "enabled" : "disabled"), null);
        return agent;
    }

    /** Generates a new plaintext token, persists only its hash, and returns the plaintext once. */
    @Transactional
    public String rotateToken(Long id) {
        Agent agent = get(id);
        String token = UUID.randomUUID().toString().replace("-", "") + TokenHasher.generateToken();
        agent.setApiKeyHash(TokenHasher.sha256Hex(token));
        agent.touch();
        auditService.record(null, "agent.token_rotated", ActorType.USER, agent.getOwner(), agent.getId(), null,
                AuditSeverity.WARNING, "API token rotated for agent '" + agent.getName() + "'", null);
        return token;
    }

    private String joinGroups(List<String> groups) {
        if (groups == null || groups.isEmpty()) {
            return null;
        }
        return String.join(",", groups);
    }
}
