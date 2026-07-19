package com.agentshield.agent;

import com.agentshield.agent.AgentDtos.AgentResponse;
import com.agentshield.agent.AgentDtos.AgentTokenResponse;
import com.agentshield.agent.AgentDtos.CreateAgentRequest;
import com.agentshield.agent.AgentDtos.CreateCredentialRequest;
import com.agentshield.agent.AgentDtos.CredentialResponse;
import com.agentshield.agent.AgentDtos.UpdateAgentRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.time.Duration;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/agents")
@Tag(name = "Agents", description = "Agent registry: registration, enable/disable, allowed tool groups, and bearer-token credential lifecycle.")
public class AgentController {

    private final AgentService agentService;
    private final AgentCredentialService credentialService;

    public AgentController(AgentService agentService, AgentCredentialService credentialService) {
        this.agentService = agentService;
        this.credentialService = credentialService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public AgentResponse create(@Valid @RequestBody CreateAgentRequest request) {
        return AgentResponse.from(agentService.create(request));
    }

    @GetMapping
    public List<AgentResponse> list() {
        return agentService.list().stream().map(AgentResponse::from).toList();
    }

    @GetMapping("/{id}")
    public AgentResponse get(@PathVariable Long id) {
        return AgentResponse.from(agentService.get(id));
    }

    @PutMapping("/{id}")
    public AgentResponse update(@PathVariable Long id, @RequestBody UpdateAgentRequest request) {
        return AgentResponse.from(agentService.update(id, request));
    }

    @PostMapping("/{id}/enable")
    public AgentResponse enable(@PathVariable Long id) {
        return AgentResponse.from(agentService.setEnabled(id, true));
    }

    @PostMapping("/{id}/disable")
    public AgentResponse disable(@PathVariable Long id) {
        return AgentResponse.from(agentService.setEnabled(id, false));
    }

    @GetMapping("/{id}/credentials")
    public List<CredentialResponse> listCredentials(@PathVariable Long id) {
        return credentialService.listForAgent(id).stream().map(CredentialResponse::from).toList();
    }

    @PostMapping("/{id}/credentials")
    @ResponseStatus(HttpStatus.CREATED)
    public AgentTokenResponse createCredential(@PathVariable Long id, @RequestBody(required = false) CreateCredentialRequest request,
            Authentication authentication) {
        Duration validFor = request != null && request.validForMinutes() != null
                ? Duration.ofMinutes(request.validForMinutes())
                : null;
        var issued = credentialService.create(id, actorName(authentication), validFor);
        return new AgentTokenResponse(id, issued.credentialId(), issued.plaintextToken());
    }

    @PostMapping("/{id}/credentials/{credentialId}/revoke")
    public void revokeCredential(@PathVariable Long id, @PathVariable Long credentialId, Authentication authentication) {
        credentialService.revoke(credentialId, actorName(authentication));
    }

    /** Kept for backward compatibility: revokes all active credentials and issues a fresh one. */
    @PostMapping("/{id}/rotate-token")
    public AgentTokenResponse rotateToken(@PathVariable Long id, Authentication authentication) {
        var issued = credentialService.rotate(id, actorName(authentication));
        return new AgentTokenResponse(id, issued.credentialId(), issued.plaintextToken());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id) {
        agentService.setEnabled(id, false);
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
