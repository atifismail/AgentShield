package com.agentshield.approval;

import com.agentshield.approval.ApprovalDtos.ApprovalDecisionRequest;
import com.agentshield.approval.ApprovalDtos.ApprovalResponse;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/approvals")
public class ApprovalController {

    private final ApprovalService approvalService;

    public ApprovalController(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    @GetMapping
    public List<ApprovalResponse> list(@RequestParam(defaultValue = "false") boolean pendingOnly) {
        var approvals = pendingOnly ? approvalService.listPending() : approvalService.listAll();
        return approvals.stream().map(ApprovalResponse::from).toList();
    }

    @GetMapping("/{id}")
    public ApprovalResponse get(@PathVariable Long id) {
        return ApprovalResponse.from(approvalService.get(id));
    }

    @PostMapping("/{id}/approve")
    public ApprovalResponse approve(@PathVariable Long id, @Valid @RequestBody ApprovalDecisionRequest request) {
        return approvalService.approve(id, request.decidedBy());
    }

    @PostMapping("/{id}/reject")
    public ApprovalResponse reject(@PathVariable Long id, @Valid @RequestBody ApprovalDecisionRequest request) {
        return approvalService.reject(id, request.decidedBy());
    }
}
