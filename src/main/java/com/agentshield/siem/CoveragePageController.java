package com.agentshield.siem;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CoveragePageController {

    private final DetectionRuleRepository ruleRepository;
    private final DetectionValidationRunRepository validationRunRepository;
    private final ObjectMapper objectMapper;

    public CoveragePageController(DetectionRuleRepository ruleRepository,
            DetectionValidationRunRepository validationRunRepository, ObjectMapper objectMapper) {
        this.ruleRepository = ruleRepository;
        this.validationRunRepository = validationRunRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/siem/coverage")
    public String coverage(Model model) {
        List<DetectionRule> rules = ruleRepository.findAllByOrderByCategoryAscCodeAsc();
        List<DetectionValidationRun> runs = validationRunRepository.findAllByOrderByCreatedAtDesc();

        Map<String, DetectionValidationRun> lastRunByRuleCode = new LinkedHashMap<>();
        for (DetectionValidationRun run : runs) {
            lastRunByRuleCode.putIfAbsent(run.getDetectionRuleCode(), run);
        }

        List<Map<String, Object>> rows = rules.stream().map(rule -> {
            Optional<DetectionValidationRun> lastRun = Optional.ofNullable(lastRunByRuleCode.get(rule.getCode()));
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("code", rule.getCode());
            row.put("name", rule.getName());
            row.put("category", rule.getCategory());
            row.put("source", rule.getSource().name());
            row.put("lastValidatedAt", lastRun.map(r -> r.getCreatedAt().toString()).orElse(null));
            row.put("lastValidationPassed", lastRun.map(DetectionValidationRun::isPassed).orElse(null));
            return row;
        }).toList();

        Map<String, Long> bySource = new LinkedHashMap<>();
        for (DetectionRule rule : rules) {
            bySource.merge(rule.getSource().name(), 1L, Long::sum);
        }

        model.addAttribute("pageTitle", "Detection Coverage");
        model.addAttribute("ruleCount", rules.size());
        model.addAttribute("validatedCount", lastRunByRuleCode.size());
        model.addAttribute("rows", rows);
        model.addAttribute("chartSeriesJson", toJson(Map.of(
                "sourceLabels", List.copyOf(bySource.keySet()),
                "sourceCounts", List.copyOf(bySource.values()))));
        return "siem/coverage";
    }

    private String toJson(Map<String, Object> value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }
}
