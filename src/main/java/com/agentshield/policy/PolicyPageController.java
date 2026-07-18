package com.agentshield.policy;

import com.agentshield.common.ActionCategory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PolicyPageController {

    private final PolicyRepository policyRepository;

    public PolicyPageController(PolicyRepository policyRepository) {
        this.policyRepository = policyRepository;
    }

    @GetMapping("/policies")
    public String list(Model model) {
        model.addAttribute("pageTitle", "Policies");
        model.addAttribute("policies", policyRepository.findAllByOrderByNameAscVersionDesc());
        model.addAttribute("actionCategories", ActionCategory.values());
        return "policies/index";
    }
}
