package com.agentshield.governance;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class GovernancePageController {

    @GetMapping("/governance")
    public String index(Model model) {
        model.addAttribute("pageTitle", "Governance Evidence Export");
        return "governance/index";
    }
}
