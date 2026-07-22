package com.agentshield.siem;

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
 * One recorded outcome of {@link AttackSimulatorService} replaying a demo-lab scenario — lets the
 * coverage dashboard show "last validated" per scenario, not just "last fired in production
 * traffic" (which the {@code agentshield_detection_rule_fired_total} metric already covers).
 */
@Entity
@Table(name = "detection_validation_runs")
@Getter
@Setter
@NoArgsConstructor
public class DetectionValidationRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scenario_code", nullable = false, length = 64)
    private String scenarioCode;

    @Column(name = "detection_rule_code", length = 64)
    private String detectionRuleCode;

    @Column(nullable = false)
    private boolean passed;

    @Column(length = 2000)
    private String detail;

    @Column(name = "triggered_by")
    private String triggeredBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
