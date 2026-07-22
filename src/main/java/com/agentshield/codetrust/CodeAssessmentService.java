package com.agentshield.codetrust;

import com.agentshield.audit.AuditService;
import com.agentshield.codetrust.CodeTrustDtos.SubmitAssessmentRequest;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.RiskLevel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Evaluates a submitted {@link CodeAssessment}: blocks it if a HIGH/CRITICAL finding is present,
 * forces it to stay PENDING if the submitter flagged it as needing a re-scan (e.g. after an
 * AI-suggested fix that wasn't independently re-verified), or passes it and issues a signed
 * {@link AiCodeReceipt} via {@link ReceiptSigningService}.
 *
 * <p>Deviates from the original plan's "route blocked assessments through the existing
 * ApprovalService/ApprovalRequest machinery": {@code ApprovalRequest} mandatorily references a
 * {@code GatewayRequest} and its {@code approve()} executes a tool call — neither concept applies
 * to reviewing a code assessment, so review state (approvedBy/approvedAt/rejectedBy/rejectedAt)
 * lives directly on {@link CodeAssessment} instead, using the same
 * {@code findByIdForUpdate}-then-transition pattern {@code ApprovalService} uses, just without a
 * separate queue entity.
 */
@Service
public class CodeAssessmentService {

    private static final Set<RiskLevel> BLOCKING_SEVERITIES = Set.of(RiskLevel.HIGH, RiskLevel.CRITICAL);

    private final CodeAssessmentRepository assessmentRepository;
    private final CodeFindingRepository findingRepository;
    private final AiCodeReceiptRepository receiptRepository;
    private final ReceiptSigningService signingService;
    private final AuditService auditService;

    public CodeAssessmentService(CodeAssessmentRepository assessmentRepository,
            CodeFindingRepository findingRepository, AiCodeReceiptRepository receiptRepository,
            ReceiptSigningService signingService, AuditService auditService) {
        this.assessmentRepository = assessmentRepository;
        this.findingRepository = findingRepository;
        this.receiptRepository = receiptRepository;
        this.signingService = signingService;
        this.auditService = auditService;
    }

    @Transactional
    public CodeAssessment submit(SubmitAssessmentRequest request) {
        CodeAssessment assessment = new CodeAssessment();
        assessment.setRepo(request.repo());
        assessment.setCommitSha(request.commitSha());
        assessment.setBranch(request.branch());
        assessment.setAuthor(request.author());
        assessment.setSource(request.source());
        assessment.setRequiresRescan(request.requiresRescan());
        assessment.setRequestedBy(request.requestedBy());
        assessment = assessmentRepository.save(assessment);

        List<CodeFinding> findings = new ArrayList<>();
        if (request.findings() != null) {
            for (var f : request.findings()) {
                CodeFinding finding = new CodeFinding();
                finding.setAssessment(assessment);
                finding.setFilePath(f.filePath());
                finding.setLine(f.line());
                finding.setCategory(f.category());
                finding.setSeverity(f.severity());
                finding.setRuleId(f.ruleId());
                finding.setMessage(f.message());
                findings.add(findingRepository.save(finding));
            }
        }

        evaluate(assessment, findings);
        return assessmentRepository.save(assessment);
    }

    @Transactional
    public CodeAssessment approve(Long id, String approvedBy) {
        CodeAssessment assessment = requireBlocked(id);
        assessment.setApprovedBy(approvedBy);
        assessment.setApprovedAt(Instant.now());
        pass(assessment, findingRepository.findByAssessmentId(id));
        auditService.record(correlationId(assessment), "codetrust.approved", ActorType.USER, approvedBy, null, null,
                AuditSeverity.INFO,
                "code assessment " + id + " (" + assessment.getRepo() + "@" + assessment.getCommitSha()
                        + ") approved by " + approvedBy,
                null);
        return assessmentRepository.save(assessment);
    }

    @Transactional
    public CodeAssessment reject(Long id, String rejectedBy) {
        CodeAssessment assessment = requireBlocked(id);
        assessment.setRejectedBy(rejectedBy);
        assessment.setRejectedAt(Instant.now());
        auditService.record(correlationId(assessment), "codetrust.rejected", ActorType.USER, rejectedBy, null, null,
                AuditSeverity.WARNING,
                "code assessment " + id + " (" + assessment.getRepo() + "@" + assessment.getCommitSha()
                        + ") rejected by " + rejectedBy,
                null);
        return assessmentRepository.save(assessment);
    }

    public CodeAssessment get(Long id) {
        return assessmentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("code assessment " + id + " not found"));
    }

    public List<CodeAssessment> listAll() {
        return assessmentRepository.findAllByOrderByCreatedAtDesc();
    }

    public List<CodeFinding> findingsFor(Long assessmentId) {
        return findingRepository.findByAssessmentId(assessmentId);
    }

    public Optional<AiCodeReceipt> receiptFor(Long assessmentId) {
        return receiptRepository.findByAssessmentId(assessmentId);
    }

    private CodeAssessment requireBlocked(Long id) {
        CodeAssessment assessment = assessmentRepository.findByIdForUpdate(id)
                .orElseThrow(() -> new ResourceNotFoundException("code assessment " + id + " not found"));
        if (!assessment.isBlocked()) {
            throw new ConflictException(
                    "code assessment " + id + " is not BLOCKED (status=" + assessment.getStatus() + ")");
        }
        return assessment;
    }

    private void evaluate(CodeAssessment assessment, List<CodeFinding> findings) {
        if (assessment.isRequiresRescan()) {
            assessment.setStatus(AssessmentStatus.PENDING);
            auditService.record(correlationId(assessment), "codetrust.pending_rescan", ActorType.SYSTEM,
                    "codetrust", null, null, AuditSeverity.WARNING,
                    "assessment for " + assessment.getRepo() + "@" + assessment.getCommitSha()
                            + " requires a re-scan (submitted as an AI-suggested fix) before it can pass",
                    null);
            return;
        }
        boolean hasBlockingFinding = findings.stream().anyMatch(f -> BLOCKING_SEVERITIES.contains(f.getSeverity()));
        if (hasBlockingFinding) {
            assessment.setStatus(AssessmentStatus.BLOCKED);
            auditService.record(correlationId(assessment), "codetrust.blocked", ActorType.SYSTEM, "codetrust",
                    null, null, AuditSeverity.WARNING,
                    "assessment for " + assessment.getRepo() + "@" + assessment.getCommitSha()
                            + " blocked: a HIGH/CRITICAL finding is present",
                    null);
            return;
        }
        pass(assessment, findings);
    }

    private void pass(CodeAssessment assessment, List<CodeFinding> findings) {
        assessment.setStatus(AssessmentStatus.PASSED);
        AiCodeReceipt receipt = signingService.sign(assessment, findings);
        receiptRepository.save(receipt);
        auditService.record(correlationId(assessment), "codetrust.passed", ActorType.SYSTEM, "codetrust", null, null,
                AuditSeverity.INFO,
                "assessment for " + assessment.getRepo() + "@" + assessment.getCommitSha()
                        + " passed; receipt issued",
                null);
    }

    private String correlationId(CodeAssessment assessment) {
        return "codetrust-" + assessment.getId();
    }
}
