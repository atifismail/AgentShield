package com.agentshield.mcp;

import com.agentshield.agent.AgentRepository;
import com.agentshield.common.ActionCategory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class McpPageController {

    private final McpServerRepository serverRepository;
    private final McpConsentService consentService;
    private final AgentRepository agentRepository;

    public McpPageController(McpServerRepository serverRepository, McpConsentService consentService,
            AgentRepository agentRepository) {
        this.serverRepository = serverRepository;
        this.consentService = consentService;
        this.agentRepository = agentRepository;
    }

    @GetMapping("/mcp-servers")
    public String list(Model model) {
        model.addAttribute("pageTitle", "MCP Servers");
        model.addAttribute("servers", serverRepository.findAll());
        model.addAttribute("consents", consentService.listAll());
        model.addAttribute("agents", agentRepository.findAll());
        model.addAttribute("authModes", McpAuthMode.values());
        model.addAttribute("transportTypes", McpTransportType.values());
        model.addAttribute("actionCategories", ActionCategory.values());
        return "mcp-servers/index";
    }
}
