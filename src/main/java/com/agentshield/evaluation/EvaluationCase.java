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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * One synthetic, redacted fixture belonging to an {@link EvaluationSuite} version. {@code
 * inputFixtureJson} is parsed as an {@link EvaluationCaseFixture} at run time — never real
 * captured tool/request data (work package 4, "Fixture rules").
 */
@Entity
@Table(name = "evaluation_cases")
@Getter
@Setter
@NoArgsConstructor
public class EvaluationCase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "suite_id", nullable = false)
    private Long suiteId;

    @Column(name = "case_key", nullable = false, length = 255)
    private String caseKey;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "input_fixture_json", nullable = false)
    private String inputFixtureJson;

    @Enumerated(EnumType.STRING)
    @Column(name = "expected_decision", nullable = false, length = 32)
    private PolicyDecisionType expectedDecision;

    @Column(name = "expected_rule_id", length = 128)
    private String expectedRuleId;

    @Column(name = "expect_no_tool_call", nullable = false)
    private boolean expectNoToolCall = true;

    @Column(length = 500)
    private String tags;

    @Column(nullable = false, length = 128)
    private String checksum;
}
