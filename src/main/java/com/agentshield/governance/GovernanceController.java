package com.agentshield.governance;

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

    public GovernanceController(GovernanceReportService service) {
        this.service = service;
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
}
