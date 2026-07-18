package com.agentshield.gateway;

import com.agentshield.approval.ApprovalRequestRepository;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.policy.PolicyDecisionRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class GatewayRequestPageController {

    private final GatewayRequestRepository repository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final ApprovalRequestRepository approvalRequestRepository;
    private final GatewayToolResponseRepository toolResponseRepository;

    public GatewayRequestPageController(GatewayRequestRepository repository,
            PolicyDecisionRepository policyDecisionRepository, ApprovalRequestRepository approvalRequestRepository,
            GatewayToolResponseRepository toolResponseRepository) {
        this.repository = repository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.approvalRequestRepository = approvalRequestRepository;
        this.toolResponseRepository = toolResponseRepository;
    }

    @GetMapping("/gateway-requests")
    public String list(@RequestParam(defaultValue = "0") int page, Model model) {
        model.addAttribute("pageTitle", "Gateway Requests");
        model.addAttribute("requestsPage",
                repository.findAllByOrderByCreatedAtDesc(PageRequest.of(page, 50, Sort.by(Sort.Direction.DESC, "createdAt"))));
        return "gateway-requests/index";
    }

    @GetMapping("/gateway-requests/{id}")
    public String detail(@PathVariable Long id, Model model) {
        GatewayRequest request = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("gateway request " + id + " not found"));
        model.addAttribute("pageTitle", "Gateway request #" + id);
        model.addAttribute("request", request);
        policyDecisionRepository.findTopByGatewayRequestIdOrderByCreatedAtDesc(id)
                .ifPresent(d -> model.addAttribute("policyDecision", d));
        approvalRequestRepository.findByGatewayRequestId(id).ifPresent(a -> model.addAttribute("approval", a));
        toolResponseRepository.findByGatewayRequestId(id).ifPresent(tr -> model.addAttribute("toolResponse", tr));
        return "gateway-requests/detail";
    }
}
