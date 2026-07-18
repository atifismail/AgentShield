package com.agentshield.agent;

import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.gateway.GatewayRequestRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class AgentPageController {

    private final AgentRepository agentRepository;
    private final AgentCredentialRepository credentialRepository;
    private final GatewayRequestRepository gatewayRequestRepository;

    public AgentPageController(AgentRepository agentRepository, AgentCredentialRepository credentialRepository,
            GatewayRequestRepository gatewayRequestRepository) {
        this.agentRepository = agentRepository;
        this.credentialRepository = credentialRepository;
        this.gatewayRequestRepository = gatewayRequestRepository;
    }

    @GetMapping("/agents")
    public String list(Model model) {
        model.addAttribute("pageTitle", "Agents");
        model.addAttribute("agents", agentRepository.findAll());
        return "agents/index";
    }

    @GetMapping("/agents/{id}")
    public String detail(@PathVariable Long id, Model model) {
        Agent agent = agentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("agent " + id + " not found"));
        model.addAttribute("pageTitle", "Agent: " + agent.getName());
        model.addAttribute("agent", agent);
        model.addAttribute("credentials", credentialRepository.findByAgentIdOrderByCreatedAtDesc(id));
        model.addAttribute("recentRequests",
                gatewayRequestRepository.findByAgentIdOrderByCreatedAtDesc(id, PageRequest.of(0, 20, Sort.by(Sort.Direction.DESC, "createdAt"))));
        return "agents/detail";
    }
}
