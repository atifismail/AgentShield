package com.agentshield.approval;

import com.agentshield.approval.ApprovalProfileDtos.ApprovalProfileResponse;
import com.agentshield.approval.ApprovalProfileDtos.CreateApprovalProfileRequest;
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
@RequestMapping("/api/approval-profiles")
@Tag(name = "Approval profiles", description = "Routes an APPROVAL_REQUIRED request to the correct human role by priority/predicate match (work package 3). ADMIN / SECURITY_ANALYST only.")
public class ApprovalProfileController {

    private final ApprovalProfileService service;

    public ApprovalProfileController(ApprovalProfileService service) {
        this.service = service;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ApprovalProfileResponse create(@Valid @RequestBody CreateApprovalProfileRequest request,
            Authentication authentication) {
        return ApprovalProfileResponse.from(service.create(request, actorName(authentication)));
    }

    @GetMapping
    public List<ApprovalProfileResponse> list() {
        return service.list().stream().map(ApprovalProfileResponse::from).toList();
    }

    @GetMapping("/{id}")
    public ApprovalProfileResponse get(@PathVariable Long id) {
        return ApprovalProfileResponse.from(service.get(id));
    }

    @PostMapping("/{id}/enable")
    public ApprovalProfileResponse enable(@PathVariable Long id, Authentication authentication) {
        return ApprovalProfileResponse.from(service.setEnabled(id, true, actorName(authentication)));
    }

    @PostMapping("/{id}/disable")
    public ApprovalProfileResponse disable(@PathVariable Long id, Authentication authentication) {
        return ApprovalProfileResponse.from(service.setEnabled(id, false, actorName(authentication)));
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
