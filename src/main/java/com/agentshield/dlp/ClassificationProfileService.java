package com.agentshield.dlp;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.dlp.DlpDtos.CreateProfileRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ClassificationProfileService {

    private final ClassificationProfileRepository repository;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    public ClassificationProfileService(ClassificationProfileRepository repository, AuditService auditService,
            ObjectMapper objectMapper) {
        this.repository = repository;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
    }

    public List<ClassificationProfile> listAll() {
        return repository.findAllByOrderByPriorityAscIdAsc();
    }

    @Transactional
    public ClassificationProfile create(CreateProfileRequest request, String createdBy) {
        ClassificationProfile profile = new ClassificationProfile();
        profile.setName(request.name());
        profile.setLocale(request.locale());
        profile.setDetectSecrets(request.detectSecrets() == null || request.detectSecrets());
        profile.setDetectPii(request.detectPii() == null || request.detectPii());
        profile.setDetectPromptInjection(request.detectPromptInjection() == null || request.detectPromptInjection());
        profile.setDefaultAction(request.defaultAction());
        profile.setPriority(request.priority() != null ? request.priority() : 100);
        profile.setCustomPatternsJson(writeJsonSafely(request.customPatterns()));
        profile.setCreatedBy(createdBy);
        profile = repository.save(profile);

        auditService.record(null, "dlp.profile_created", ActorType.USER, createdBy, null, null, AuditSeverity.INFO,
                "DLP classification profile " + profile.getId() + " created: " + profile.getName(), null);
        return profile;
    }

    @Transactional
    public ClassificationProfile setEnabled(Long id, boolean enabled, String actor) {
        ClassificationProfile profile = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("classification profile " + id + " not found"));
        profile.setEnabled(enabled);
        auditService.record(null, enabled ? "dlp.profile_enabled" : "dlp.profile_disabled", ActorType.USER, actor,
                null, null, AuditSeverity.INFO, "DLP classification profile " + id + " " + (enabled ? "enabled" : "disabled"),
                null);
        return profile;
    }

    private String writeJsonSafely(List<String> customPatterns) {
        if (customPatterns == null || customPatterns.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(customPatterns);
        } catch (Exception e) {
            return null;
        }
    }
}
