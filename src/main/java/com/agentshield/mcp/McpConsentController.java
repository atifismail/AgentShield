package com.agentshield.mcp;

import com.agentshield.mcp.McpConsentDtos.ConsentResponse;
import com.agentshield.mcp.McpConsentDtos.CreateConsentRequest;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/mcp-consents")
@Tag(name = "MCP consents", description = "Per-agent, per-MCP-server (optionally per-tool/action-category) consent grants — the confused-deputy control gating every MCP-backed tool call.")
public class McpConsentController {

    private final McpConsentService service;

    public McpConsentController(McpConsentService service) {
        this.service = service;
    }

    @GetMapping
    public List<ConsentResponse> list(@RequestParam(required = false) Long agentId,
            @RequestParam(required = false) Long mcpServerId) {
        List<McpConsent> consents;
        if (agentId != null) {
            consents = service.listForAgent(agentId);
        } else if (mcpServerId != null) {
            consents = service.listForServer(mcpServerId);
        } else {
            consents = service.listAll();
        }
        return consents.stream().map(ConsentResponse::from).toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ConsentResponse create(@Valid @RequestBody CreateConsentRequest request, Authentication authentication) {
        return ConsentResponse.from(service.create(request, actorName(authentication)));
    }

    @PostMapping("/{id}/revoke")
    public ConsentResponse revoke(@PathVariable Long id, Authentication authentication) {
        return ConsentResponse.from(service.revoke(id, actorName(authentication)));
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
