package com.agentshield.siem;

import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import java.util.List;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SIEM-normalized export and the attack-simulator trigger (improvement_plan.md A5). The export
 * endpoint works in any deployment; {@code /validate} only replays scenarios against the bundled
 * demo mock tools and seeded demo agents, so — like {@code /demo/**} itself — it only makes sense,
 * and is only reachable, when the {@code demo} Spring profile is active.
 */
@RestController
@RequestMapping("/api/siem")
@Tag(name = "SIEM", description = "Normalized event export for SIEM/SOAR ingest, plus the bundled attack-scenario detection validator (demo profile only).")
public class SiemController {

    private final SiemEventExportService exportService;
    private final AttackSimulatorService attackSimulatorService;
    private final Environment environment;

    public SiemController(SiemEventExportService exportService, AttackSimulatorService attackSimulatorService,
            Environment environment) {
        this.exportService = exportService;
        this.attackSimulatorService = attackSimulatorService;
        this.environment = environment;
    }

    @GetMapping(value = "/export", params = "format=ndjson", produces = "application/x-ndjson")
    public ResponseEntity<String> exportNdjson(@RequestParam Instant from, @RequestParam Instant to) {
        String ndjson = exportService.toNdjson(exportService.export(from, to));
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-ndjson"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"agentshield-events.ndjson\"")
                .body(ndjson);
    }

    @GetMapping("/export")
    public List<SiemEventDtos.SiemEvent> exportJson(@RequestParam Instant from, @RequestParam Instant to) {
        return exportService.export(from, to);
    }

    @PostMapping("/validate")
    public List<AttackSimulatorService.ScenarioResult> validate() {
        if (!environment.acceptsProfiles(Profiles.of("demo"))) {
            throw new IllegalStateException(
                    "the attack simulator only runs against the bundled demo mock tools/seeded agents "
                            + "(agentshield.stdio-style 'demo' profile is not active)");
        }
        return attackSimulatorService.runAll();
    }
}
