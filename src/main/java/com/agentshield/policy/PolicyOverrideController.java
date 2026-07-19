package com.agentshield.policy;

import com.agentshield.policy.PolicyOverrideDtos.CreateOverrideRequest;
import com.agentshield.policy.PolicyOverrideDtos.OverrideResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/policy-overrides")
@Tag(name = "Policy overrides", description = "Database-backed rules layered on top of the fixed default policy, evaluated last, without redeploying code.")
public class PolicyOverrideController {

    private final PolicyOverrideService service;

    public PolicyOverrideController(PolicyOverrideService service) {
        this.service = service;
    }

    @GetMapping
    public List<OverrideResponse> list() {
        return service.listAll().stream().map(OverrideResponse::from).toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public OverrideResponse create(@Valid @RequestBody CreateOverrideRequest request, Authentication authentication) {
        return OverrideResponse.from(service.create(request, actorName(authentication)));
    }

    @PostMapping("/{id}/enable")
    public OverrideResponse enable(@PathVariable Long id, Authentication authentication) {
        return OverrideResponse.from(service.setEnabled(id, true, actorName(authentication)));
    }

    @PostMapping("/{id}/disable")
    public OverrideResponse disable(@PathVariable Long id, Authentication authentication) {
        return OverrideResponse.from(service.setEnabled(id, false, actorName(authentication)));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id, Authentication authentication) {
        service.delete(id, actorName(authentication));
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
