package com.agentshield.policy;

import com.agentshield.common.ActionCategory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PolicyPageController {

    private final PolicyRepository policyRepository;
    private final PolicyOverrideService overrideService;

    public PolicyPageController(PolicyRepository policyRepository, PolicyOverrideService overrideService) {
        this.policyRepository = policyRepository;
        this.overrideService = overrideService;
    }

    @GetMapping("/policies")
    public String list(Model model) {
        model.addAttribute("pageTitle", "Policies");
        model.addAttribute("policies", policyRepository.findAllByOrderByNameAscVersionDesc());
        model.addAttribute("overrides", overrideService.listAll());
        model.addAttribute("actionCategories", ActionCategory.values());
        return "policies/index";
    }
}
