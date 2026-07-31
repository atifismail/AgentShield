package com.agentshield.grant;

import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.grant.GrantDtos.CreateGrantRequest;
import com.agentshield.grant.GrantDtos.GrantResponse;
import com.agentshield.grant.GrantDtos.RevokeGrantRequest;
import com.agentshield.tool.ToolRepository;
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
@RequestMapping("/api/agents/{agentId}/grants")
@Tag(name = "Agent tool grants", description = "Explicit, expiring per-agent tool grants — the data-driven alternative to Agent.allowedToolGroups (work package 2). ADMIN only for mutations; SECURITY_ANALYST may read.")
public class AgentToolGrantController {

    private final AgentToolGrantService service;
    private final ToolRepository toolRepository;

    public AgentToolGrantController(AgentToolGrantService service, ToolRepository toolRepository) {
        this.service = service;
        this.toolRepository = toolRepository;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public GrantResponse create(@PathVariable Long agentId, @Valid @RequestBody CreateGrantRequest request,
            Authentication authentication) {
        AgentToolGrant grant = service.create(agentId, request, actorName(authentication));
        return toResponse(grant);
    }

    @GetMapping
    public List<GrantResponse> list(@PathVariable Long agentId) {
        return service.list(agentId).stream().map(this::toResponse).toList();
    }

    @PostMapping("/{grantId}/revoke")
    public GrantResponse revoke(@PathVariable Long agentId, @PathVariable Long grantId,
            @RequestBody(required = false) RevokeGrantRequest request, Authentication authentication) {
        String reason = request == null ? null : request.reason();
        AgentToolGrant grant = service.revoke(agentId, grantId, reason, actorName(authentication));
        return toResponse(grant);
    }

    private GrantResponse toResponse(AgentToolGrant grant) {
        String toolName = toolRepository.findById(grant.getToolId())
                .map(t -> t.getName())
                .orElseThrow(() -> new ResourceNotFoundException("tool " + grant.getToolId() + " not found"));
        return GrantResponse.from(grant, toolName);
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
