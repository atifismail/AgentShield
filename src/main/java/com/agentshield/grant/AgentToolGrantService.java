package com.agentshield.grant;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentRepository;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.ValidationException;
import com.agentshield.grant.GrantDtos.CreateGrantRequest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Create/list/revoke for {@link AgentToolGrant} (agentshield_policy_evidence_execution_plan_2026
 * -07-30.md work package 2). Matching/enforcement lives in {@link GrantEvaluationService} — this
 * service only owns the CRUD-and-validation lifecycle.
 */
@Service
public class AgentToolGrantService {

    private final AgentToolGrantRepository repository;
    private final AgentRepository agentRepository;
    private final ToolRepository toolRepository;
    private final AuditService auditService;

    public AgentToolGrantService(AgentToolGrantRepository repository, AgentRepository agentRepository,
            ToolRepository toolRepository, AuditService auditService) {
        this.repository = repository;
        this.agentRepository = agentRepository;
        this.toolRepository = toolRepository;
        this.auditService = auditService;
    }

    @Transactional
    public AgentToolGrant create(Long agentId, CreateGrantRequest request, String createdBy) {
        Agent agent = agentRepository.findById(agentId)
                .orElseThrow(() -> new ResourceNotFoundException("agent " + agentId + " not found"));
        Tool tool = toolRepository.findById(request.toolId())
                .orElseThrow(() -> new ResourceNotFoundException("tool " + request.toolId() + " not found"));

        if (request.notBefore() != null && request.expiresAt() != null && !request.expiresAt().isAfter(request.notBefore())) {
            throw new ValidationException("expiresAt must be after notBefore");
        }

        String resourcePathPattern = blankToNull(request.resourcePathPattern());
        if (resourcePathPattern != null) {
            var validation = ResourcePathPatternValidator.validate(resourcePathPattern);
            if (!validation.allowed()) {
                throw new ValidationException("invalid resource path pattern: " + validation.reason());
            }
        }

        AgentToolGrant grant = new AgentToolGrant();
        grant.setAgentId(agent.getId());
        grant.setToolId(tool.getId());
        grant.setStatus(GrantStatus.ACTIVE);
        grant.setActionCategory(request.actionCategory());
        grant.setTargetEnvironment(blankToNull(request.targetEnvironment()));
        grant.setResourcePathPattern(resourcePathPattern);
        grant.setRequiredTokenScope(blankToNull(request.requiredTokenScope()));
        grant.setNotBefore(request.notBefore());
        grant.setExpiresAt(request.expiresAt());
        grant.setCreatedBy(createdBy);
        grant.setReason(blankToNull(request.reason()));
        grant = repository.save(grant);

        auditService.record(null, "grant.created", ActorType.USER, createdBy, agent.getId(), tool.getId(),
                AuditSeverity.INFO,
                "grant " + grant.getId() + " created for agent '" + agent.getName() + "' on tool '" + tool.getName()
                        + "'",
                Map.of("grantId", String.valueOf(grant.getId()), "actionCategory",
                        String.valueOf(grant.getActionCategory()), "targetEnvironment",
                        String.valueOf(grant.getTargetEnvironment())));
        return grant;
    }

    public List<AgentToolGrant> list(Long agentId) {
        agentRepository.findById(agentId)
                .orElseThrow(() -> new ResourceNotFoundException("agent " + agentId + " not found"));
        return repository.findByAgentIdOrderByCreatedAtDesc(agentId);
    }

    @Transactional
    public AgentToolGrant revoke(Long agentId, Long grantId, String reason, String revokedBy) {
        AgentToolGrant grant = repository.findByIdAndAgentId(grantId, agentId)
                .orElseThrow(() -> new ResourceNotFoundException("grant " + grantId + " not found for agent " + agentId));
        if (grant.getStatus() == GrantStatus.REVOKED) {
            throw new ConflictException("grant " + grantId + " is already revoked");
        }
        grant.setStatus(GrantStatus.REVOKED);
        grant.setRevokedBy(revokedBy);
        grant.setRevokedAt(Instant.now());
        grant.setReason(blankToNull(reason) != null ? blankToNull(reason) : grant.getReason());
        grant.touch();

        auditService.record(null, "grant.revoked", ActorType.USER, revokedBy, grant.getAgentId(), grant.getToolId(),
                AuditSeverity.WARNING, "grant " + grant.getId() + " revoked by " + revokedBy,
                Map.of("grantId", String.valueOf(grant.getId())));
        return grant;
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
