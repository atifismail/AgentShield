package com.agentshield.governance;

import com.agentshield.common.ValidationException;
import com.agentshield.governance.EvidenceExportDtos.EvidenceBundle;
import com.agentshield.governance.GovernanceReportDtos.GovernanceReport;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/governance")
@Tag(name = "Governance", description = "AI RMF-mapped evidence export: agents, approved tools, denied actions, approvals, drift, incidents, and policy versions for a date range.")
public class GovernanceController {

    private final GovernanceReportService service;
    private final EvidenceExportService evidenceExportService;

    public GovernanceController(GovernanceReportService service, EvidenceExportService evidenceExportService) {
        this.service = service;
        this.evidenceExportService = evidenceExportService;
    }

    @GetMapping("/report")
    public GovernanceReport report(@RequestParam Instant from, @RequestParam Instant to) {
        return service.generate(from, to);
    }

    @GetMapping(value = "/report", params = "format=markdown")
    public ResponseEntity<String> reportMarkdown(@RequestParam Instant from, @RequestParam Instant to) {
        String markdown = service.renderMarkdown(service.generate(from, to));
        return ResponseEntity.ok()
                .contentType(MediaType.valueOf("text/markdown"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"governance-report.md\"")
                .body(markdown);
    }

    /**
     * Versioned evidence bundle (work package 5). JSON is canonical; {@code format=sarif} is a
     * constrained compatibility projection of policy/evaluation findings only.
     */
    @GetMapping("/evidence")
    public ResponseEntity<?> evidence(@RequestParam Instant from, @RequestParam Instant to,
            @RequestParam(defaultValue = "json") String format) {
        EvidenceBundle bundle = evidenceExportService.generate(from, to);
        if ("sarif".equalsIgnoreCase(format)) {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"agentshield-evidence.sarif\"")
                    .body(evidenceExportService.toSarif(bundle));
        }
        if (!"json".equalsIgnoreCase(format)) {
            throw new ValidationException("format must be 'json' or 'sarif'");
        }
        return ResponseEntity.ok(bundle);
    }
}
