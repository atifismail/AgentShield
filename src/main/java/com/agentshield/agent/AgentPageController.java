package com.agentshield.agent;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AgentPageController {

    private final AgentRepository agentRepository;

    public AgentPageController(AgentRepository agentRepository) {
        this.agentRepository = agentRepository;
    }

    @GetMapping("/agents")
    public String list(Model model) {
        model.addAttribute("pageTitle", "Agents");
        model.addAttribute("agents", agentRepository.findAll());
        return "agents/index";
    }
}
