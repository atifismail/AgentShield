package com.agentshield.evaluation;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Immutable, versioned corpus of {@link EvaluationCase}s (agentshield_policy_evidence_execution
 * _plan_2026-07-30.md work package 4). Editing an existing suite's cases always creates a new
 * {@code (name, version)} row rather than mutating one in place — historical
 * {@link EvaluationRun}s stay reproducible against the exact version they ran.
 */
@Entity
@Table(name = "evaluation_suites")
@Getter
@Setter
@NoArgsConstructor
public class EvaluationSuite {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(nullable = false)
    private int version;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private EvaluationSuiteStatus status = EvaluationSuiteStatus.ACTIVE;

    @Column(length = 2000)
    private String description;

    @Column(nullable = false, length = 128)
    private String checksum;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
