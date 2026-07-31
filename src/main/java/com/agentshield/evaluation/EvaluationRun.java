package com.agentshield.evaluation;

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

@Entity
@Table(name = "evaluation_runs")
@Getter
@Setter
@NoArgsConstructor
public class EvaluationRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "suite_id", nullable = false)
    private Long suiteId;

    @Column(name = "suite_version", nullable = false)
    private int suiteVersion;

    /** Identifies which grant-transition-mode/policy configuration this run was evaluated against. */
    @Column(name = "policy_config_fingerprint", length = 128)
    private String policyConfigFingerprint;

    @Column(name = "triggered_by")
    private String triggeredBy;

    @Column(name = "started_at", nullable = false)
    private Instant startedAt = Instant.now();

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "total_cases", nullable = false)
    private int totalCases;

    @Column(name = "passed_cases", nullable = false)
    private int passedCases;

    @Column(name = "failed_cases", nullable = false)
    private int failedCases;

    @Column(name = "error_cases", nullable = false)
    private int errorCases;
}
