package com.agentshield.siem.validation;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One run of {@link AlertImportService} against an externally-imported alert export — distinct
 * from {@code com.agentshield.siem.DetectionValidationRun} (Phase 2), which records
 * {@code AttackSimulatorService}'s own in-process scenario replays against AgentShield's own
 * detections. This entity is for the vendor-neutral question: did a downstream SIEM actually
 * produce the alerts AgentShield's scenario catalog says it should have.
 */
@Entity
@Table(name = "validation_runs")
@Getter
@Setter
@NoArgsConstructor
public class ValidationRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "triggered_by")
    private String triggeredBy;

    @Column(name = "matched_count", nullable = false)
    private int matchedCount;

    @Column(name = "missed_count", nullable = false)
    private int missedCount;

    @Column(name = "unexpected_count", nullable = false)
    private int unexpectedCount;

    @Column(name = "matched_scenarios_json", length = 4000)
    private String matchedScenariosJson;

    @Column(name = "missed_scenarios_json", length = 4000)
    private String missedScenariosJson;

    @Column(name = "unexpected_alerts_json", length = 4000)
    private String unexpectedAlertsJson;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
