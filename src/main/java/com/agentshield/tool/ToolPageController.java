package com.agentshield.tool;

import com.agentshield.common.ResourceNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class ToolPageController {

    private final ToolRepository toolRepository;
    private final ToolVersionRepository toolVersionRepository;
    private final ToolProvenanceService provenanceService;

    public ToolPageController(ToolRepository toolRepository, ToolVersionRepository toolVersionRepository,
            ToolProvenanceService provenanceService) {
        this.toolRepository = toolRepository;
        this.toolVersionRepository = toolVersionRepository;
        this.provenanceService = provenanceService;
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
        List<ToolVersion> versions = toolVersionRepository.findByToolIdOrderByDetectedAtDesc(id);
        model.addAttribute("pageTitle", "Tool: " + tool.getName());
        model.addAttribute("tool", tool);
        model.addAttribute("versions", versions);
        provenanceService.latestForTool(id).ifPresent(p -> model.addAttribute("provenance", p));

        if (tool.hasDrift()) {
            Optional<ToolVersion> approved = versions.stream().filter(v -> v.getStatus() == ToolVersionStatus.APPROVED).findFirst();
            Optional<ToolVersion> current = versions.stream().findFirst();
            if (approved.isPresent() && current.isPresent() && !approved.get().getId().equals(current.get().getId())) {
                model.addAttribute("driftDiff", diffLines(
                        approved.get().getDescription() + "\n" + approved.get().getSchemaJson(),
                        current.get().getDescription() + "\n" + current.get().getSchemaJson()));
            }
        }
        return "tools/detail";
    }

    /**
     * Line-by-line comparison (by position, not a full LCS diff) between the last-approved and
     * current tool fingerprint text — enough for an operator to see what changed without pulling
     * in a diff library for what is normally a handful of lines of JSON schema + description.
     */
    private List<DiffLine> diffLines(String approvedText, String currentText) {
        String[] approvedLines = approvedText.split("\n", -1);
        String[] currentLines = currentText.split("\n", -1);
        int max = Math.max(approvedLines.length, currentLines.length);
        List<DiffLine> result = new ArrayList<>();
        for (int i = 0; i < max; i++) {
            String oldLine = i < approvedLines.length ? approvedLines[i] : null;
            String newLine = i < currentLines.length ? currentLines[i] : null;
            if (java.util.Objects.equals(oldLine, newLine)) {
                result.add(new DiffLine("same", newLine));
            } else {
                if (oldLine != null) {
                    result.add(new DiffLine("removed", oldLine));
                }
                if (newLine != null) {
                    result.add(new DiffLine("added", newLine));
                }
            }
        }
        return result;
    }

    public record DiffLine(String type, String text) {
    }
}
