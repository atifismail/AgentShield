package com.agentshield.codetrust;

import com.agentshield.common.RiskLevel;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.List;

public final class CodeTrustDtos {

    private CodeTrustDtos() {
    }

    public record FindingRequest(
            String filePath,
            Integer line,
            @NotNull FindingCategory category,
            @NotNull RiskLevel severity,
            String ruleId,
            String message
    ) {
    }

    public record SubmitAssessmentRequest(
            @NotBlank String repo,
            @NotBlank String commitSha,
            String branch,
            String author,
            @NotNull AssessmentSource source,
            boolean requiresRescan,
            String requestedBy,
            @Valid List<FindingRequest> findings
    ) {
    }

    public record FindingResponse(Long id, String filePath, Integer line, FindingCategory category,
            RiskLevel severity, String ruleId, String message, FindingStatus status) {
        static FindingResponse from(CodeFinding f) {
            return new FindingResponse(f.getId(), f.getFilePath(), f.getLine(), f.getCategory(), f.getSeverity(),
                    f.getRuleId(), f.getMessage(), f.getStatus());
        }
    }

    public record ReceiptResponse(Long id, String commitSha, String sbomHash, String scanSummaryHash,
            String algorithm, String signature, String signerKeyId, Instant createdAt) {
        static ReceiptResponse from(AiCodeReceipt r) {
            return new ReceiptResponse(r.getId(), r.getCommitSha(), r.getSbomHash(), r.getScanSummaryHash(),
                    r.getAlgorithm(), r.getSignature(), r.getSignerKeyId(), r.getCreatedAt());
        }
    }

    public record AssessmentResponse(
            Long id,
            String repo,
            String commitSha,
            String branch,
            String author,
            AssessmentSource source,
            AssessmentStatus status,
            boolean requiresRescan,
            String requestedBy,
            String approvedBy,
            Instant approvedAt,
            String rejectedBy,
            Instant rejectedAt,
            Instant createdAt,
            List<FindingResponse> findings,
            ReceiptResponse receipt
    ) {
        static AssessmentResponse from(CodeAssessment a, List<CodeFinding> findings, AiCodeReceipt receipt) {
            return new AssessmentResponse(a.getId(), a.getRepo(), a.getCommitSha(), a.getBranch(), a.getAuthor(),
                    a.getSource(), a.getStatus(), a.isRequiresRescan(), a.getRequestedBy(), a.getApprovedBy(),
                    a.getApprovedAt(), a.getRejectedBy(), a.getRejectedAt(), a.getCreatedAt(),
                    findings.stream().map(FindingResponse::from).toList(),
                    receipt == null ? null : ReceiptResponse.from(receipt));
        }
    }

    public record ReviewDecisionRequest(@NotBlank String decidedBy) {
    }

    public record VerifyReceiptResponse(boolean valid, String commitSha, String scanSummaryHash, String signerKeyId) {
    }
}
