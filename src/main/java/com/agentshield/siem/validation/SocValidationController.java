package com.agentshield.siem.validation;

import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.siem.AttackSimulatorService;
import com.agentshield.siem.validation.SocValidationDtos.ImportAlertsRequest;
import com.agentshield.siem.validation.SocValidationDtos.ImportAlertsResponse;
import com.agentshield.siem.validation.SocValidationDtos.ImportedAlertRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/**
 * The vendor-neutral half of the SOC Validation Module (improvement_plan.md N1, folded into
 * AgentShield rather than a separate product): re-runs the extended attack-scenario simulator on
 * demand, and lets an operator import an externally-exported alert list to check whether their
 * own SIEM actually produced the alerts AgentShield's scenario catalog says it should have.
 * Covered by the same {@code /api/siem/**} role gate as the rest of this package
 * (ADMIN/SECURITY_ANALYST, see {@code SecurityConfig}).
 */
@RestController
@RequestMapping("/api/siem/validation")
@Tag(name = "SOC Validation", description = "Extended attack-scenario simulator trigger, alert-import validation against an "
        + "expected-detections manifest, and coverage reports.")
public class SocValidationController {

    private final AttackSimulatorService attackSimulatorService;
    private final AlertImportService alertImportService;
    private final ValidationRunRepository validationRunRepository;
    private final Environment environment;
    private final ObjectMapper objectMapper;

    public SocValidationController(AttackSimulatorService attackSimulatorService,
            AlertImportService alertImportService, ValidationRunRepository validationRunRepository,
            Environment environment, ObjectMapper objectMapper) {
        this.attackSimulatorService = attackSimulatorService;
        this.alertImportService = alertImportService;
        this.validationRunRepository = validationRunRepository;
        this.environment = environment;
        this.objectMapper = objectMapper;
    }

    /** Equivalent to {@code POST /api/siem/validate} (Phase 2) under this module's namespace — same
     * demo-profile-only gating, since it replays scenarios against the bundled demo mock tools. */
    @PostMapping("/scenarios/run")
    public List<AttackSimulatorService.ScenarioResult> runScenarios() {
        requireDemoProfile();
        return attackSimulatorService.runAll();
    }

    @PostMapping("/alerts/import")
    public ImportAlertsResponse importAlerts(@Valid @RequestBody ImportAlertsRequest request,
            Authentication authentication) {
        List<ImportedAlert> alerts = request.alerts().stream().map(ImportedAlertRequest::toImportedAlert).toList();
        var result = alertImportService.evaluate(ExpectedDetectionsManifest.defaultManifest(), alerts);

        List<String> unexpectedNames = result.unexpectedAlerts().stream()
                .map(a -> a.alertName() == null ? "(unnamed)" : a.alertName())
                .toList();

        ValidationRun run = new ValidationRun();
        run.setTriggeredBy(actorName(authentication));
        run.setMatchedCount(result.matchedScenarios().size());
        run.setMissedCount(result.missedScenarios().size());
        run.setUnexpectedCount(result.unexpectedAlerts().size());
        run.setMatchedScenariosJson(toJson(result.matchedScenarios()));
        run.setMissedScenariosJson(toJson(result.missedScenarios()));
        run.setUnexpectedAlertsJson(toJson(unexpectedNames));
        run = validationRunRepository.save(run);

        return new ImportAlertsResponse(run.getId(), run.getMatchedCount(), run.getMissedCount(),
                run.getUnexpectedCount(), result.matchedScenarios(), result.missedScenarios(), unexpectedNames);
    }

    @GetMapping("/runs/{id}/report")
    public ResponseEntity<String> report(@PathVariable Long id, @RequestParam(defaultValue = "md") String format) {
        ValidationRun run = validationRunRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("validation run " + id + " not found"));
        if ("html".equalsIgnoreCase(format)) {
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(renderHtml(run));
        }
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("text/markdown")).body(renderMarkdown(run));
    }

    private void requireDemoProfile() {
        if (!environment.acceptsProfiles(Profiles.of("demo"))) {
            throw new IllegalStateException(
                    "the attack simulator only runs against the bundled demo mock tools/seeded agents "
                            + "('demo' profile is not active)");
        }
    }

    private String renderMarkdown(ValidationRun run) {
        StringBuilder sb = new StringBuilder();
        sb.append("# SOC Validation Report — Run #").append(run.getId()).append("\n\n");
        sb.append("Triggered by: ").append(nullToDash(run.getTriggeredBy())).append("\n\n");
        sb.append("Generated: ").append(run.getCreatedAt()).append("\n\n");
        sb.append("| Matched | Missed | Unexpected |\n|---|---|---|\n");
        sb.append("| ").append(run.getMatchedCount()).append(" | ").append(run.getMissedCount()).append(" | ")
                .append(run.getUnexpectedCount()).append(" |\n\n");
        sb.append("## Matched scenarios\n\n").append(listFromJson(run.getMatchedScenariosJson()));
        sb.append("\n## Missed scenarios\n\n").append(listFromJson(run.getMissedScenariosJson()));
        sb.append("\n## Unexpected alerts (not tied to any expected scenario)\n\n")
                .append(listFromJson(run.getUnexpectedAlertsJson()));
        return sb.toString();
    }

    private String renderHtml(ValidationRun run) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body><h1>SOC Validation Report — Run #").append(run.getId()).append("</h1>");
        sb.append("<p>Triggered by: ").append(HtmlUtils.htmlEscape(nullToDash(run.getTriggeredBy()))).append("</p>");
        sb.append("<p>Generated: ").append(run.getCreatedAt()).append("</p>");
        sb.append("<p>Matched: ").append(run.getMatchedCount()).append(" · Missed: ")
                .append(run.getMissedCount()).append(" · Unexpected: ").append(run.getUnexpectedCount())
                .append("</p>");
        sb.append("<h2>Matched scenarios</h2>").append(htmlListFromJson(run.getMatchedScenariosJson()));
        sb.append("<h2>Missed scenarios</h2>").append(htmlListFromJson(run.getMissedScenariosJson()));
        sb.append("<h2>Unexpected alerts</h2>").append(htmlListFromJson(run.getUnexpectedAlertsJson()));
        sb.append("</body></html>");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private List<String> readJsonList(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, List.class);
        } catch (Exception e) {
            return List.of();
        }
    }

    private String listFromJson(String json) {
        List<String> values = readJsonList(json);
        if (values.isEmpty()) {
            return "_none_\n";
        }
        StringBuilder sb = new StringBuilder();
        for (String value : values) {
            sb.append("- ").append(value).append("\n");
        }
        return sb.toString();
    }

    private String htmlListFromJson(String json) {
        List<String> values = readJsonList(json);
        if (values.isEmpty()) {
            return "<p><em>none</em></p>";
        }
        StringBuilder sb = new StringBuilder("<ul>");
        for (String value : values) {
            sb.append("<li>").append(HtmlUtils.htmlEscape(value)).append("</li>");
        }
        sb.append("</ul>");
        return sb.toString();
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "[]";
        }
    }

    private String nullToDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
