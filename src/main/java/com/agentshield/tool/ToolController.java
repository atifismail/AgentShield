package com.agentshield.tool;

import com.agentshield.tool.ToolDtos.ApprovalDecisionRequest;
import com.agentshield.tool.ToolDtos.RegisterToolRequest;
import com.agentshield.tool.ToolDtos.ToolResponse;
import com.agentshield.tool.ToolDtos.ToolVersionResponse;
import com.agentshield.tool.ToolDtos.UpdateToolFingerprintRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tools")
@Tag(name = "Tools", description = "Tool registry: registration, schema/description fingerprinting, drift detection, and approval.")
public class ToolController {

    private final ToolService toolService;

    public ToolController(ToolService toolService) {
        this.toolService = toolService;
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
}
