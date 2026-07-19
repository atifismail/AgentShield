package com.agentshield.tool;

import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.tool.ToolDtos.ApprovalDecisionRequest;
import com.agentshield.tool.ToolDtos.RegisterToolRequest;
import com.agentshield.tool.ToolDtos.RevokeProvenanceRequest;
import com.agentshield.tool.ToolDtos.ToolProvenanceResponse;
import com.agentshield.tool.ToolDtos.ToolResponse;
import com.agentshield.tool.ToolDtos.ToolVersionResponse;
import com.agentshield.tool.ToolDtos.UpdateToolFingerprintRequest;
import com.agentshield.tool.ToolDtos.VerifySignatureRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tools")
@Tag(name = "Tools", description = "Tool registry: registration, schema/description fingerprinting, drift detection, approval, and supply-chain provenance.")
public class ToolController {

    private final ToolService toolService;
    private final ToolProvenanceService provenanceService;

    public ToolController(ToolService toolService, ToolProvenanceService provenanceService) {
        this.toolService = toolService;
        this.provenanceService = provenanceService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ToolResponse register(@Valid @RequestBody RegisterToolRequest request) {
        return ToolResponse.from(toolService.register(request));
    }

    @GetMapping
    public List<ToolResponse> list() {
        return toolService.list().stream().map(ToolResponse::from).toList();
    }

    @GetMapping("/{id}")
    public ToolResponse get(@PathVariable Long id) {
        return ToolResponse.from(toolService.get(id));
    }

    @GetMapping("/{id}/versions")
    public List<ToolVersionResponse> versions(@PathVariable Long id) {
        return toolService.listVersions(id).stream().map(ToolVersionResponse::from).toList();
    }

    @PostMapping("/{id}/refresh")
    public ToolResponse refresh(@PathVariable Long id, @RequestBody UpdateToolFingerprintRequest request) {
        return ToolResponse.from(toolService.refreshFingerprint(id, request.schemaJson(), request.description()));
    }

    @PostMapping("/{id}/approve")
    public ToolResponse approve(@PathVariable Long id, @Valid @RequestBody ApprovalDecisionRequest request) {
        return ToolResponse.from(toolService.approveLatestVersion(id, request.decidedBy()));
    }

    @PostMapping("/{id}/reject")
    public ToolResponse reject(@PathVariable Long id, @Valid @RequestBody ApprovalDecisionRequest request) {
        return ToolResponse.from(toolService.rejectLatestVersion(id, request.decidedBy()));
    }

    @GetMapping("/{id}/provenance")
    public ToolProvenanceResponse provenance(@PathVariable Long id) {
        return provenanceService.latestForTool(id).map(ToolProvenanceResponse::from)
                .orElseThrow(() -> new ResourceNotFoundException("tool " + id + " has no provenance record yet"));
    }

    @PostMapping("/{id}/provenance/verify")
    public ToolProvenanceResponse verifySignature(@PathVariable Long id, @Valid @RequestBody VerifySignatureRequest request,
            Authentication authentication) {
        return ToolProvenanceResponse.from(provenanceService.verifySignature(id, request.bundleJson(),
                request.expectedIdentity(), request.expectedIssuer(), actorName(authentication)));
    }

    @PostMapping("/{id}/provenance/revoke")
    public ToolProvenanceResponse revokeProvenance(@PathVariable Long id, @Valid @RequestBody RevokeProvenanceRequest request,
            Authentication authentication) {
        ToolProvenance current = provenanceService.latestForTool(id)
                .orElseThrow(() -> new ResourceNotFoundException("tool " + id + " has no provenance record yet"));
        return ToolProvenanceResponse.from(
                provenanceService.revoke(current.getId(), request.reason(), actorName(authentication)));
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
