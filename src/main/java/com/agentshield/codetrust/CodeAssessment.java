package com.agentshield.codetrust;

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
 * One submitted AI-coding-assistant scan result for a repo/commit. A {@link CodeAssessment} is
 * evaluated synchronously on submit (see {@code CodeAssessmentService.submit}) into PASSED or
 * BLOCKED; a BLOCKED assessment can be reviewed by a human via {@code approve}/{@code reject} —
 * mirroring {@code com.agentshield.approval.ApprovalRequest}'s status/decision fields and its
 * {@code findByIdForUpdate} row-locking pattern, but as fields directly on this entity rather than
 * a separate approval-queue row, since {@code ApprovalRequest} requires a mandatory
 * {@code GatewayRequest} and its {@code approve()} executes a tool call — neither applies here
 * (there is no gateway request or tool call involved in reviewing a code assessment).
 */
@Entity
@Table(name = "code_assessments")
@Getter
@Setter
@NoArgsConstructor
public class CodeAssessment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 512)
    private String repo;

    @Column(name = "commit_sha", nullable = false, length = 64)
    private String commitSha;

    @Column(length = 255)
    private String branch;

    @Column(length = 255)
    private String author;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AssessmentSource source;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AssessmentStatus status = AssessmentStatus.PENDING;

    /**
     * Set when this assessment supersedes a prior one that required a re-scan after an
     * AI-suggested fix — forces this assessment back to PENDING evaluation semantics even if no
     * blocking finding is otherwise present, until a human/CI re-confirms it. See
     * {@code CodeAssessmentService}.
     */
    @Column(name = "requires_rescan", nullable = false)
    private boolean requiresRescan;

    @Column(name = "requested_by", length = 255)
    private String requestedBy;

    @Column(name = "approved_by", length = 255)
    private String approvedBy;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "rejected_by", length = 255)
    private String rejectedBy;

    @Column(name = "rejected_at")
    private Instant rejectedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public boolean isBlocked() {
        return status == AssessmentStatus.BLOCKED;
    }
}
