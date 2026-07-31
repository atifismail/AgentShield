package com.agentshield.tool;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.TokenHasher;
import com.agentshield.common.ValidationException;
import com.agentshield.gateway.OutboundEndpointValidator;
import com.agentshield.metrics.GatewayMetrics;
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
    private final OutboundEndpointValidator outboundEndpointValidator;
    private final GatewayMetrics metrics;
    private final ToolProvenanceService provenanceService;
    private final ToolFingerprintService fingerprintService;

    public ToolService(ToolRepository toolRepository, ToolVersionRepository versionRepository,
            AuditService auditService, OutboundEndpointValidator outboundEndpointValidator, GatewayMetrics metrics,
            ToolProvenanceService provenanceService, ToolFingerprintService fingerprintService) {
        this.toolRepository = toolRepository;
        this.versionRepository = versionRepository;
        this.auditService = auditService;
        this.outboundEndpointValidator = outboundEndpointValidator;
        this.metrics = metrics;
        this.provenanceService = provenanceService;
        this.fingerprintService = fingerprintService;
    }

    /** A newly registered tool starts PENDING: it cannot be called until a human approves its first version. */
    @Transactional
    public Tool register(RegisterToolRequest request) {
        toolRepository.findByName(request.name()).ifPresent(t -> {
            throw new ConflictException("a tool named '" + request.name() + "' already exists");
        });
        var validation = outboundEndpointValidator.validate(request.endpointUrl());
        if (!validation.allowed()) {
            throw new ValidationException("endpoint URL rejected by outbound policy: " + validation.reason());
        }
        Tool tool = new Tool();
        tool.setName(request.name());
        tool.setType(request.type());
        tool.setToolGroup(request.toolGroup() == null || request.toolGroup().isBlank() ? "default" : request.toolGroup());
        tool.setEndpointUrl(request.endpointUrl());
        tool.setOwner(request.owner());
        tool.setEnvironment(request.environment());
        tool.setDescription(request.description());
        tool.setSchemaJson(request.schemaJson());
        tool.setOutputSchemaJson(request.outputSchemaJson());
        String hash = fingerprint(request.schemaJson(), request.description());
        tool.setCurrentHash(hash);
        String descriptionHash = fingerprintService.hashDescription(request.description());
        String inputSchemaHash = fingerprintService.hashJson(request.schemaJson());
        String outputSchemaHash = fingerprintService.hashJson(request.outputSchemaJson());
        tool.setDescriptionHash(descriptionHash);
        tool.setInputSchemaHash(inputSchemaHash);
        tool.setOutputSchemaHash(outputSchemaHash);
        tool.setRiskTier(request.riskTier() == null ? ToolRiskTier.UNCLASSIFIED : request.riskTier());
        tool.setDefaultAction(request.defaultAction() == null ? ToolDefaultAction.REVIEW : request.defaultAction());
        tool.setApprovalStatus(ToolApprovalStatus.PENDING);
        tool.setSourceType(ToolSourceType.CUSTOM_HTTP);
        tool.setLastSeenAt(Instant.now());
        tool = toolRepository.save(tool);

        ToolVersion version = new ToolVersion();
        version.setTool(tool);
        version.setSchemaJson(request.schemaJson());
        version.setDescription(request.description());
        version.setHash(hash);
        version.setDescriptionHash(descriptionHash);
        version.setInputSchemaHash(inputSchemaHash);
        version.setOutputSchemaHash(outputSchemaHash);
        version.setOutputSchemaJson(request.outputSchemaJson());
        version.setStatus(ToolVersionStatus.DETECTED);
        version = versionRepository.save(version);
        provenanceService.recordChecksum(version);

        auditService.record(null, "tool.registered", ActorType.USER, tool.getOwner(), null, tool.getId(),
                AuditSeverity.INFO, "tool '" + tool.getName() + "' registered, pending approval", null);
        return tool;
    }

    /**
     * Registers a new tool, or re-fingerprints an existing one, discovered from an external
     * source (currently: MCP server discovery — see com.agentshield.mcp.McpDiscoveryService).
     * Reuses the exact same drift-detection semantics as a manually {@link #register}ed tool.
     */
    @Transactional
    public Tool upsertDiscoveredTool(String name, ToolType type, String toolGroup, String endpointUrl, String owner,
            String environment, String description, String schemaJson, String outputSchemaJson, Long mcpServerId,
            String mcpToolName) {
        return toolRepository.findByName(name)
                .map(existing -> refreshFingerprint(existing.getId(), schemaJson, description, outputSchemaJson, null, null))
                .orElseGet(() -> {
                    Tool tool = new Tool();
                    tool.setName(name);
                    tool.setType(type);
                    tool.setToolGroup(toolGroup == null || toolGroup.isBlank() ? "default" : toolGroup);
                    tool.setEndpointUrl(endpointUrl);
                    tool.setOwner(owner);
                    tool.setEnvironment(environment);
                    tool.setDescription(description);
                    tool.setSchemaJson(schemaJson);
                    tool.setOutputSchemaJson(outputSchemaJson);
                    tool.setMcpServerId(mcpServerId);
                    tool.setMcpToolName(mcpToolName);
                    String hash = fingerprint(schemaJson, description);
                    tool.setCurrentHash(hash);
                    String descriptionHash = fingerprintService.hashDescription(description);
                    String inputSchemaHash = fingerprintService.hashJson(schemaJson);
                    String outputSchemaHash = fingerprintService.hashJson(outputSchemaJson);
                    tool.setDescriptionHash(descriptionHash);
                    tool.setInputSchemaHash(inputSchemaHash);
                    tool.setOutputSchemaHash(outputSchemaHash);
                    tool.setApprovalStatus(ToolApprovalStatus.PENDING);
                    tool.setSourceType(ToolSourceType.MCP);
                    tool.setLastSeenAt(Instant.now());
                    Tool saved = toolRepository.save(tool);

                    ToolVersion version = new ToolVersion();
                    version.setTool(saved);
                    version.setSchemaJson(schemaJson);
                    version.setDescription(description);
                    version.setHash(hash);
                    version.setDescriptionHash(descriptionHash);
                    version.setInputSchemaHash(inputSchemaHash);
                    version.setOutputSchemaHash(outputSchemaHash);
                    version.setOutputSchemaJson(outputSchemaJson);
                    version.setStatus(ToolVersionStatus.DETECTED);
                    version = versionRepository.save(version);
                    provenanceService.recordChecksum(version);

                    auditService.record(null, "tool.registered_from_mcp", ActorType.SYSTEM, "mcp-discovery", null,
                            saved.getId(), AuditSeverity.INFO,
                            "tool '" + saved.getName() + "' discovered from MCP server, pending approval", null);
                    return saved;
                });
    }

    public Tool get(Long id) {
        return toolRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("tool " + id + " not found"));
    }

    public List<Tool> list() {
        return toolRepository.findAll();
    }

    public List<ToolVersion> listVersions(Long toolId) {
        return versionRepository.findByToolIdOrderByDetectedAtDescIdDesc(toolId);
    }

    /**
     * Re-fingerprints a tool's live schema/description/output-schema. If the legacy combined hash
     * changed from the last approved hash, or the independent output-schema fingerprint changed
     * from the last approved version's, the tool is marked DRIFTED and a new pending
     * {@link ToolVersion} is recorded — it stays blocked until a human re-approves it (threat
     * model: tool poisoning / metadata drift). {@code riskTier}/{@code defaultAction} are applied
     * as plain metadata updates and never contribute to the drift decision by themselves — a
     * classification change is never mistaken for a supply-chain drift signal.
     */
    @Transactional
    public Tool refreshFingerprint(Long id, String schemaJson, String description, String outputSchemaJson,
            ToolRiskTier riskTier, ToolDefaultAction defaultAction) {
        Tool tool = get(id);
        String hash = fingerprint(schemaJson, description);
        String descriptionHash = fingerprintService.hashDescription(description);
        String inputSchemaHash = fingerprintService.hashJson(schemaJson);
        String outputSchemaHash = fingerprintService.hashJson(outputSchemaJson);

        tool.setSchemaJson(schemaJson);
        tool.setDescription(description);
        tool.setOutputSchemaJson(outputSchemaJson);
        tool.setCurrentHash(hash);
        tool.setDescriptionHash(descriptionHash);
        tool.setInputSchemaHash(inputSchemaHash);
        tool.setOutputSchemaHash(outputSchemaHash);
        tool.setLastSeenAt(Instant.now());
        if (riskTier != null) {
            tool.setRiskTier(riskTier);
        }
        if (defaultAction != null) {
            tool.setDefaultAction(defaultAction);
        }

        String approvedOutputSchemaHash = approvedVersion(tool).map(ToolVersion::getOutputSchemaHash).orElse(null);
        boolean legacyDrift = !hash.equals(tool.getApprovedHash());
        boolean outputDrift = !java.util.Objects.equals(outputSchemaHash, approvedOutputSchemaHash);

        if (legacyDrift || outputDrift) {
            tool.setApprovalStatus(ToolApprovalStatus.DRIFTED);
            ToolVersion version = new ToolVersion();
            version.setTool(tool);
            version.setSchemaJson(schemaJson);
            version.setDescription(description);
            version.setHash(hash);
            version.setDescriptionHash(descriptionHash);
            version.setInputSchemaHash(inputSchemaHash);
            version.setOutputSchemaHash(outputSchemaHash);
            version.setOutputSchemaJson(outputSchemaJson);
            version.setStatus(ToolVersionStatus.DETECTED);
            version = versionRepository.save(version);
            provenanceService.recordChecksum(version);

            auditService.record(null, "tool.drift_detected", ActorType.SYSTEM, null, null, tool.getId(),
                    AuditSeverity.WARNING,
                    "tool '" + tool.getName() + "' schema/description/output-schema changed; drifted from approved version",
                    null);
            metrics.toolDriftDetected();
        }
        tool.touch();
        return tool;
    }

    private java.util.Optional<ToolVersion> approvedVersion(Tool tool) {
        return versionRepository.findByToolIdOrderByDetectedAtDescIdDesc(tool.getId()).stream()
                .filter(v -> v.getStatus() == ToolVersionStatus.APPROVED)
                .findFirst();
    }

    @Transactional
    public Tool approveLatestVersion(Long id, String approvedBy) {
        Tool tool = get(id);
        ToolVersion latest = latestVersion(tool);
        provenanceService.requireSignatureIfPolicyMandates(tool, latest);

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
        return versionRepository.findByToolIdOrderByDetectedAtDescIdDesc(tool.getId()).stream()
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("tool " + tool.getId() + " has no versions"));
    }

    private String fingerprint(String schemaJson, String description) {
        String content = (schemaJson == null ? "" : schemaJson) + "" + (description == null ? "" : description);
        return TokenHasher.sha256Hex(content);
    }
}
