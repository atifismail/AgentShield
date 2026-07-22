package com.agentshield.approval;

import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.common.ApprovalStatus;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.gateway.GatewayToolResponseRepository;
import com.agentshield.policy.PolicyDecisionRepository;
import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ApprovalPageController {

    private final ApprovalRequestRepository repository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final GatewayToolResponseRepository toolResponseRepository;
    private final GatewayRequestRepository gatewayRequestRepository;
    private final AgentCredentialRepository agentCredentialRepository;

    public ApprovalPageController(ApprovalRequestRepository repository,
            PolicyDecisionRepository policyDecisionRepository, GatewayToolResponseRepository toolResponseRepository,
            GatewayRequestRepository gatewayRequestRepository, AgentCredentialRepository agentCredentialRepository) {
        this.repository = repository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.toolResponseRepository = toolResponseRepository;
        this.gatewayRequestRepository = gatewayRequestRepository;
        this.agentCredentialRepository = agentCredentialRepository;
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

    /**
     * Full decision context for a single approval (improvement_plan.md P2 "Human Approval UX
     * Needs Context Completeness") — everything an approver needs to make a real production
     * decision without leaving this page: agent identity/credential, tool/environment, policy
     * reason, risk score, any detector findings already on record, and the agent's recent call
     * history, plus an explicit statement that approving executes the tool call immediately.
     */
    @GetMapping("/approvals/{id}")
    public String detail(@PathVariable Long id, Model model) {
        ApprovalRequest approval = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("approval " + id + " not found"));
        GatewayRequest gatewayRequest = approval.getGatewayRequest();
        model.addAttribute("pageTitle", "Approval #" + id);
        model.addAttribute("approval", approval);
        model.addAttribute("request", gatewayRequest);

        policyDecisionRepository.findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc(gatewayRequest.getId())
                .ifPresent(d -> model.addAttribute("policyDecision", d));
        toolResponseRepository.findByGatewayRequestId(gatewayRequest.getId())
                .ifPresent(tr -> model.addAttribute("toolResponse", tr));

        agentCredentialRepository.findByAgentIdOrderByCreatedAtDesc(gatewayRequest.getAgent().getId()).stream()
                .filter(c -> c.getStatus() == CredentialStatus.ACTIVE)
                .findFirst()
                .ifPresent(c -> model.addAttribute("credentialPrefix", c.getTokenPrefix()));

        List<GatewayRequest> priorCalls = gatewayRequestRepository
                .findByAgentIdOrderByCreatedAtDesc(gatewayRequest.getAgent().getId(), PageRequest.of(0, 6))
                .stream()
                .filter(r -> !r.getId().equals(gatewayRequest.getId()))
                .limit(5)
                .toList();
        model.addAttribute("priorCalls", priorCalls);

        return "approvals/detail";
    }
}
