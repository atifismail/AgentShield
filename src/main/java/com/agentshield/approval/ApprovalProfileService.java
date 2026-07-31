package com.agentshield.approval;

import com.agentshield.approval.ApprovalProfileDtos.CreateApprovalProfileRequest;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.ValidationException;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * CRUD/lifecycle for {@link ApprovalProfile}; matching/routing itself lives in
 * {@link ApprovalProfileResolutionService}. Predicates are immutable once created in this
 * release — only the enabled flag can be toggled — so "update" is limited to enable/disable,
 * deliberately avoiding the added complexity of reconciling in-flight ambiguity against arbitrary
 * partial field edits.
 */
@Service
public class ApprovalProfileService {

    private final ApprovalProfileRepository repository;
    private final AuditService auditService;

    public ApprovalProfileService(ApprovalProfileRepository repository, AuditService auditService) {
        this.repository = repository;
        this.auditService = auditService;
    }

    @Transactional
    public ApprovalProfile create(CreateApprovalProfileRequest request, String createdBy) {
        if (repository.existsByName(request.name())) {
            throw new ConflictException("an approval profile named '" + request.name() + "' already exists");
        }

        ApprovalProfile profile = new ApprovalProfile();
        profile.setName(request.name());
        profile.setDescription(request.description());
        profile.setPriority(request.priority());
        profile.setAgentId(request.agentId());
        profile.setToolId(request.toolId());
        profile.setToolGroup(blankToNull(request.toolGroup()));
        profile.setActionCategory(request.actionCategory());
        profile.setTargetEnvironment(blankToNull(request.targetEnvironment()));
        profile.setRiskTier(request.riskTier());
        profile.setTargetRole(request.targetRole());
        profile.setExpirationMinutes(request.expirationMinutes());
        profile.setCreatedBy(createdBy);
        profile.setEnabled(true);

        rejectIfAmbiguous(profile);
        profile = repository.save(profile);

        auditService.record(null, "approval_profile.created", ActorType.USER, createdBy, null, null,
                AuditSeverity.INFO, "approval profile '" + profile.getName() + "' created", Map.of("profileId",
                        String.valueOf(profile.getId()), "priority", String.valueOf(profile.getPriority())));
        return profile;
    }

    public List<ApprovalProfile> list() {
        return repository.findAll();
    }

    public ApprovalProfile get(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("approval profile " + id + " not found"));
    }

    @Transactional
    public ApprovalProfile setEnabled(Long id, boolean enabled, String actor) {
        ApprovalProfile profile = get(id);
        if (enabled) {
            rejectIfAmbiguous(profile);
        }
        profile.setEnabled(enabled);
        profile.touch();
        auditService.record(null, enabled ? "approval_profile.enabled" : "approval_profile.disabled",
                ActorType.USER, actor, null, null, AuditSeverity.INFO,
                "approval profile '" + profile.getName() + "' " + (enabled ? "enabled" : "disabled"),
                Map.of("profileId", String.valueOf(profile.getId())));
        return profile;
    }

    /**
     * "Equal priority collisions are a configuration error" (work package 3): reject creating or
     * re-enabling a profile that would be indistinguishable in priority and predicates from
     * another currently-enabled profile — resolution order between them would be undefined.
     */
    private void rejectIfAmbiguous(ApprovalProfile candidate) {
        for (ApprovalProfile existing : repository.findByPriorityAndEnabledTrue(candidate.getPriority())) {
            if (!existing.getId().equals(candidate.getId()) && existing.hasSamePredicatesAs(candidate)) {
                throw new ValidationException("approval profile '" + candidate.getName()
                        + "' is ambiguous with enabled profile '" + existing.getName() + "' at priority "
                        + candidate.getPriority() + " (identical predicates)");
            }
        }
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
