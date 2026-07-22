package com.agentshield.siem.validation;

import com.agentshield.siem.AttackSimulatorService;
import com.agentshield.siem.DetectionRule;
import com.agentshield.siem.DetectionRuleRepository;
import com.agentshield.siem.DetectionValidationRun;
import com.agentshield.siem.DetectionValidationRunRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * SOC Validation dashboard — extends Phase 2's rule-centric Detection Coverage page
 * ({@code /siem/coverage}) with a scenario-centric view (all 13 implemented scenarios, in
 * {@link AttackSimulatorService#SCENARIO_CATALOG}, plus an explicit "not applicable" row for the
 * certificate-expiry scenario the original N1 plan listed but this codebase doesn't cover), MITRE
 * ATT&amp;CK/OWASP mapping columns, and the latest alert-import validation result.
 */
@Controller
public class SocValidationPageController {

    private final DetectionValidationRunRepository scenarioRunRepository;
    private final ValidationRunRepository alertImportRunRepository;
    private final DetectionRuleRepository ruleRepository;
    private final ObjectMapper objectMapper;

    public SocValidationPageController(DetectionValidationRunRepository scenarioRunRepository,
            ValidationRunRepository alertImportRunRepository, DetectionRuleRepository ruleRepository,
            ObjectMapper objectMapper) {
        this.scenarioRunRepository = scenarioRunRepository;
        this.alertImportRunRepository = alertImportRunRepository;
        this.ruleRepository = ruleRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/siem/validation")
    public String validation(Model model) {
        List<DetectionValidationRun> allScenarioRuns = scenarioRunRepository.findAllByOrderByCreatedAtDesc();
        Map<String, DetectionValidationRun> lastRunByScenario = new LinkedHashMap<>();
        for (DetectionValidationRun run : allScenarioRuns) {
            lastRunByScenario.putIfAbsent(run.getScenarioCode(), run);
        }

        Map<String, DetectionRule> rulesByCode = ruleRepository.findAll().stream()
                .collect(Collectors.toMap(DetectionRule::getCode, r -> r, (a, b) -> a));

        List<Map<String, Object>> rows = new ArrayList<>();
        for (AttackSimulatorService.ScenarioCatalogEntry entry : AttackSimulatorService.SCENARIO_CATALOG) {
            Optional<DetectionValidationRun> lastRun = Optional.ofNullable(lastRunByScenario.get(entry.code()));
            DetectionRule rule = entry.expectedDetectionRuleCode() == null ? null
                    : rulesByCode.get(entry.expectedDetectionRuleCode());
            rows.add(row(entry.code(), entry.description(),
                    rule == null ? "-" : rule.getCategory(),
                    rule == null || rule.getMitreAttackId() == null ? "-" : rule.getMitreAttackId(),
                    lastRun.map(r -> r.getCreatedAt().toString()).orElse(null),
                    lastRun.map(DetectionValidationRun::isPassed).orElse(null)));
        }
        // Explicit N/A row: the original N1 plan's 14th scenario (certificate-expiry-near-miss) is
        // a TrustAtlas concept — this codebase has no certificate management to test against, so
        // it is listed as excluded rather than silently omitted. See AttackSimulatorService javadoc.
        rows.add(row("n/a", "Certificate expiry near miss", "N/A — TrustAtlas scope", "-", null, null));

        List<ValidationRun> alertRuns = alertImportRunRepository.findAllByOrderByCreatedAtDesc();
        ValidationRun latestAlertRun = alertRuns.isEmpty() ? null : alertRuns.get(0);

        Map<String, Object> chartSeries = new LinkedHashMap<>();
        chartSeries.put("labels", List.of("Matched", "Missed", "Unexpected"));
        chartSeries.put("counts", latestAlertRun == null ? List.of(0, 0, 0)
                : List.of(latestAlertRun.getMatchedCount(), latestAlertRun.getMissedCount(),
                        latestAlertRun.getUnexpectedCount()));

        model.addAttribute("pageTitle", "SOC Validation");
        model.addAttribute("rows", rows);
        model.addAttribute("latestAlertRun", latestAlertRun);
        model.addAttribute("chartSeriesJson", toJson(chartSeries));
        return "siem/validation";
    }

    private Map<String, Object> row(String code, String description, String category, String mitreAttackId,
            String lastValidatedAt, Boolean lastPassed) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("code", code);
        row.put("description", description);
        row.put("category", category);
        row.put("mitreAttackId", mitreAttackId);
        row.put("lastValidatedAt", lastValidatedAt);
        row.put("lastPassed", lastPassed);
        return row;
    }

    private String toJson(Map<String, Object> value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }
}
