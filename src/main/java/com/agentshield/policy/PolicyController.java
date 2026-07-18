package com.agentshield.policy;

import com.agentshield.policy.PolicyDtos.CreateVersionRequest;
import com.agentshield.policy.PolicyDtos.DryRunRequest;
import com.agentshield.policy.PolicyDtos.DryRunResponse;
import com.agentshield.policy.PolicyDtos.PolicyResponse;
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
@RequestMapping("/api/policies")
public class PolicyController {

    private final PolicyService policyService;

    public PolicyController(PolicyService policyService) {
        this.policyService = policyService;
    }

    @GetMapping
    public List<PolicyResponse> list() {
        return policyService.listAll().stream().map(PolicyResponse::from).toList();
    }

    @GetMapping("/{name}/versions")
    public List<PolicyResponse> versions(@PathVariable String name) {
        return policyService.versionsOf(name).stream().map(PolicyResponse::from).toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PolicyResponse createVersion(@Valid @RequestBody CreateVersionRequest request) {
        return PolicyResponse.from(
                policyService.createVersion(request.name(), request.ruleJson(), request.mode(), request.createdBy()));
    }

    @PostMapping("/{id}/enable")
    public PolicyResponse enable(@PathVariable Long id) {
        return PolicyResponse.from(policyService.setEnabled(id, true));
    }

    @PostMapping("/{id}/disable")
    public PolicyResponse disable(@PathVariable Long id) {
        return PolicyResponse.from(policyService.setEnabled(id, false));
    }

    @PostMapping("/dry-run")
    public DryRunResponse dryRun(@Valid @RequestBody DryRunRequest request) {
        return DryRunResponse.from(policyService.dryRun(request));
    }
}
