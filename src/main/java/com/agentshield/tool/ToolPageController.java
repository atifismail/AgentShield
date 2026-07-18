package com.agentshield.tool;

import com.agentshield.common.ResourceNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class ToolPageController {

    private final ToolRepository toolRepository;
    private final ToolVersionRepository toolVersionRepository;

    public ToolPageController(ToolRepository toolRepository, ToolVersionRepository toolVersionRepository) {
        this.toolRepository = toolRepository;
        this.toolVersionRepository = toolVersionRepository;
    }

    @GetMapping("/tools")
    public String list(Model model) {
        model.addAttribute("pageTitle", "Tools");
        model.addAttribute("tools", toolRepository.findAll());
        model.addAttribute("toolTypes", ToolType.values());
        return "tools/index";
    }

    @GetMapping("/tools/{id}")
    public String detail(@PathVariable Long id, Model model) {
        Tool tool = toolRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("tool " + id + " not found"));
        model.addAttribute("pageTitle", "Tool: " + tool.getName());
        model.addAttribute("tool", tool);
        model.addAttribute("versions", toolVersionRepository.findByToolIdOrderByDetectedAtDesc(id));
        return "tools/detail";
    }
}
