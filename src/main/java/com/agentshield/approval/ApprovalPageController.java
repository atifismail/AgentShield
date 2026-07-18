package com.agentshield.approval;

import com.agentshield.common.ApprovalStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ApprovalPageController {

    private final ApprovalRequestRepository repository;

    public ApprovalPageController(ApprovalRequestRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/approvals")
    public String list(@RequestParam(defaultValue = "true") boolean pendingOnly, Model model) {
        model.addAttribute("pageTitle", "Approvals");
        model.addAttribute("approvals", pendingOnly
                ? repository.findByStatusOrderByCreatedAtAsc(ApprovalStatus.PENDING)
                : repository.findAllByOrderByCreatedAtDesc());
        model.addAttribute("pendingOnly", pendingOnly);
        return "approvals/index";
    }
}
