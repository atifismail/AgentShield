package com.agentshield.policy;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.policy.PolicyOverrideDtos.CreateOverrideRequest;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PolicyOverrideService {

    private final PolicyOverrideRepository repository;
    private final AuditService auditService;

    public PolicyOverrideService(PolicyOverrideRepository repository, AuditService auditService) {
        this.repository = repository;
        this.auditService = auditService;
    }

    public List<PolicyOverride> listAll() {
        return repository.findAllByOrderByPriorityAscIdAsc();
    }

    @Transactional
    public PolicyOverride create(CreateOverrideRequest request, String createdBy) {
        PolicyOverride override = new PolicyOverride();
        override.setActionCategory(request.actionCategory());
        override.setTargetEnvironment(request.targetEnvironment());
        override.setToolGroup(request.toolGroup());
        override.setAgentName(request.agentName());
        override.setDecision(request.decision());
        override.setReason(request.reason());
        override.setPriority(request.priority() != null ? request.priority() : 100);
        override.setCreatedBy(createdBy);
        override = repository.save(override);

        auditService.record(null, "policy.override_created", ActorType.USER, createdBy, null, null,
                AuditSeverity.WARNING,
                "policy override " + override.getId() + " created: " + describe(override), null);
        return override;
    }

    @Transactional
    public PolicyOverride setEnabled(Long id, boolean enabled, String actor) {
        PolicyOverride override = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("policy override " + id + " not found"));
        override.setEnabled(enabled);
        auditService.record(null, enabled ? "policy.override_enabled" : "policy.override_disabled", ActorType.USER,
                actor, null, null, AuditSeverity.WARNING,
                "policy override " + id + " " + (enabled ? "enabled" : "disabled"), null);
        return override;
    }

    @Transactional
    public void delete(Long id, String actor) {
        PolicyOverride override = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("policy override " + id + " not found"));
        repository.delete(override);
        auditService.record(null, "policy.override_deleted", ActorType.USER, actor, null, null, AuditSeverity.WARNING,
                "policy override " + id + " deleted: " + describe(override), null);
    }

    private String describe(PolicyOverride o) {
        return "decision=" + o.getDecision() + ", actionCategory=" + o.getActionCategory()
                + ", environment=" + o.getTargetEnvironment() + ", toolGroup=" + o.getToolGroup()
                + ", agent=" + o.getAgentName();
    }
}
