package com.agentshield.evaluation;

import com.agentshield.common.PolicyDecisionType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "evaluation_results")
@Getter
@Setter
@NoArgsConstructor
public class EvaluationResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "run_id", nullable = false)
    private Long runId;

    @Column(name = "case_id", nullable = false)
    private Long caseId;

    @Enumerated(EnumType.STRING)
    @Column(name = "actual_decision", length = 32)
    private PolicyDecisionType actualDecision;

    @Column(name = "actual_rule_id", length = 128)
    private String actualRuleId;

    @Enumerated(EnumType.STRING)
    @Column(name = "result_status", nullable = false, length = 32)
    private EvaluationResultStatus resultStatus;

    /** Never the raw fixture payload — a short, redacted explanation only. */
    @Column(name = "redacted_reason", length = 2000)
    private String redactedReason;

    @Column(name = "duration_millis", nullable = false)
    private long durationMillis;

    @Column(name = "evaluator_version", nullable = false, length = 32)
    private String evaluatorVersion;
}
