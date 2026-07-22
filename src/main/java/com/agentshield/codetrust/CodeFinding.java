package com.agentshield.codetrust;

import com.agentshield.common.RiskLevel;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A single finding within a {@link CodeAssessment}. Severity reuses {@link RiskLevel}
 * (LOW/MEDIUM/HIGH/CRITICAL) rather than a new enum — same scale the rest of the codebase already
 * scores risk on.
 */
@Entity
@Table(name = "code_findings")
@Getter
@Setter
@NoArgsConstructor
public class CodeFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "assessment_id", nullable = false)
    private CodeAssessment assessment;

    @Column(name = "file_path", length = 1024)
    private String filePath;

    private Integer line;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private FindingCategory category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private RiskLevel severity;

    @Column(name = "rule_id", length = 128)
    private String ruleId;

    @Column(length = 2000)
    private String message;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private FindingStatus status = FindingStatus.OPEN;
}
