package com.agentshield.tool;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.TokenHasher;
import com.agentshield.tool.ToolDtos.RegisterToolRequest;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Tool registration, schema/description fingerprinting, and drift detection
 * (PROJECT_PLAN.md section 5.2 / threat model "tool poisoning").
 */
@Service
public class ToolService {

    private final ToolRepository toolRepository;
    private final ToolVersionRepository versionRepository;
    private final AuditService auditService;

    public ToolService(ToolRepository toolRepository, ToolVersionRepository versionRepository,
            AuditService auditService) {
        this.toolRepository = toolRepository;
        this.versionRepository = versionRepository;
        this.auditService = auditService;
    }

    /** A newly registered tool starts PENDING: it cannot be called until a human approves its first version. */
    @Transactional
    public Tool register(RegisterToolRequest request) {
        toolRepository.findByName(request.name()).ifPresent(t -> {
            throw new ConflictException("a tool named '" + request.name() + "' already exists");
        });
        Tool tool = new Tool();
        tool.setName(request.name());
        tool.setType(request.type());
        tool.setToolGroup(request.toolGroup() == null || request.toolGroup().isBlank() ? "default" : request.toolGroup());
        tool.setEndpointUrl(request.endpointUrl());
        tool.setOwner(request.owner());
        tool.setEnvironment(request.environment());
        tool.setDescription(request.description());
        tool.setSchemaJson(request.schemaJson());
        String hash = fingerprint(request.schemaJson(), request.description());
        tool.setCurrentHash(hash);
        tool.setApprovalStatus(ToolApprovalStatus.PENDING);
        tool.setLastSeenAt(Instant.now());
        tool = toolRepository.save(tool);

        ToolVersion version = new ToolVersion();
        version.setTool(tool);
        version.setSchemaJson(request.schemaJson());
        version.setDescription(request.description());
        version.setHash(hash);
        version.setStatus(ToolVersionStatus.DETECTED);
        versionRepository.save(version);

        auditService.record(null, "tool.registered", ActorType.USER, tool.getOwner(), null, tool.getId(),
                AuditSeverity.INFO, "tool '" + tool.getName() + "' registered, pending approval", null);
        return tool;
    }

    public Tool get(Long id) {
        return toolRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("tool " + id + " not found"));
    }

    public List<Tool> list() {
        return toolRepository.findAll();
    }

    public List<ToolVersion> listVersions(Long toolId) {
        return versionRepository.findByToolIdOrderByDetectedAtDesc(toolId);
    }

    /**
     * Re-fingerprints a tool's live schema/description. If the hash changed from the last
     * approved hash, the tool is marked DRIFTED and a new pending {@link ToolVersion} is recorded —
     * it stays blocked until a human re-approves it (threat model: tool poisoning / metadata drift).
     */
    @Transactional
    public Tool refreshFingerprint(Long id, String schemaJson, String description) {
        Tool tool = get(id);
        String hash = fingerprint(schemaJson, description);
        tool.setSchemaJson(schemaJson);
        tool.setDescription(description);
        tool.setCurrentHash(hash);
        tool.setLastSeenAt(Instant.now());

        if (!hash.equals(tool.getApprovedHash())) {
            tool.setApprovalStatus(ToolApprovalStatus.DRIFTED);
            ToolVersion version = new ToolVersion();
            version.setTool(tool);
            version.setSchemaJson(schemaJson);
            version.setDescription(description);
            version.setHash(hash);
            version.setStatus(ToolVersionStatus.DETECTED);
            versionRepository.save(version);

            auditService.record(null, "tool.drift_detected", ActorType.SYSTEM, null, null, tool.getId(),
                    AuditSeverity.WARNING,
                    "tool '" + tool.getName() + "' schema/description changed; drifted from approved version",
                    null);
        }
        tool.touch();
        return tool;
    }

    @Transactional
    public Tool approveLatestVersion(Long id, String approvedBy) {
        Tool tool = get(id);
        ToolVersion latest = latestVersion(tool);
        latest.setStatus(ToolVersionStatus.APPROVED);
        latest.setApprovedBy(approvedBy);
        latest.setApprovedAt(Instant.now());

        tool.setApprovedHash(latest.getHash());
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.touch();

        auditService.record(null, "tool.approved", ActorType.USER, approvedBy, null, tool.getId(),
                AuditSeverity.INFO, "tool '" + tool.getName() + "' version approved by " + approvedBy, null);
        return tool;
    }

    @Transactional
    public Tool rejectLatestVersion(Long id, String rejectedBy) {
        Tool tool = get(id);
        ToolVersion latest = latestVersion(tool);
        latest.setStatus(ToolVersionStatus.REJECTED);
        latest.setApprovedBy(rejectedBy);
        latest.setApprovedAt(Instant.now());

        tool.setApprovalStatus(ToolApprovalStatus.REJECTED);
        tool.touch();

        auditService.record(null, "tool.rejected", ActorType.USER, rejectedBy, null, tool.getId(),
                AuditSeverity.WARNING, "tool '" + tool.getName() + "' version rejected by " + rejectedBy, null);
        return tool;
    }

    private ToolVersion latestVersion(Tool tool) {
        return versionRepository.findByToolIdOrderByDetectedAtDesc(tool.getId()).stream()
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("tool " + tool.getId() + " has no versions"));
    }

    private String fingerprint(String schemaJson, String description) {
        String content = (schemaJson == null ? "" : schemaJson) + "" + (description == null ? "" : description);
        return TokenHasher.sha256Hex(content);
    }
}
