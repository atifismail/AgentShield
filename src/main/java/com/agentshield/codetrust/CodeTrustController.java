package com.agentshield.codetrust;

import com.agentshield.codetrust.CodeTrustDtos.AssessmentResponse;
import com.agentshield.codetrust.CodeTrustDtos.ReviewDecisionRequest;
import com.agentshield.codetrust.CodeTrustDtos.SubmitAssessmentRequest;
import com.agentshield.codetrust.CodeTrustDtos.VerifyReceiptResponse;
import com.agentshield.common.ResourceNotFoundException;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Submission/review surface for AI-coding-assistant scan results. {@code POST /assessments} is
 * the CLI/CI-facing endpoint (see {@code scripts/agentshield-code-scan.sh}) — not a SAST engine
 * itself, just an ingestion and policy point for whatever findings the caller already produced.
 */
@RestController
@RequestMapping("/api/codetrust")
@Tag(name = "Code Trust", description = "AI-coding-assistant scan submission, block/pass policy, human review of blocked "
        + "assessments, and signed/verifiable receipts for passed ones.")
public class CodeTrustController {

    private final CodeAssessmentService assessmentService;
    private final ReceiptSigningService signingService;
    private final ReceiptSigningKeyProvider keyProvider;

    public CodeTrustController(CodeAssessmentService assessmentService, ReceiptSigningService signingService,
            ReceiptSigningKeyProvider keyProvider) {
        this.assessmentService = assessmentService;
        this.signingService = signingService;
        this.keyProvider = keyProvider;
    }

    @PostMapping("/assessments")
    @ResponseStatus(HttpStatus.CREATED)
    public AssessmentResponse submit(@Valid @RequestBody SubmitAssessmentRequest request) {
        return toResponse(assessmentService.submit(request));
    }

    @GetMapping("/assessments")
    public List<AssessmentResponse> list() {
        return assessmentService.listAll().stream().map(this::toResponse).toList();
    }

    @GetMapping("/assessments/{id}")
    public AssessmentResponse get(@PathVariable Long id) {
        return toResponse(assessmentService.get(id));
    }

    @PostMapping("/assessments/{id}/approve")
    public AssessmentResponse approve(@PathVariable Long id, @Valid @RequestBody ReviewDecisionRequest request) {
        return toResponse(assessmentService.approve(id, request.decidedBy()));
    }

    @PostMapping("/assessments/{id}/reject")
    public AssessmentResponse reject(@PathVariable Long id, @Valid @RequestBody ReviewDecisionRequest request) {
        return toResponse(assessmentService.reject(id, request.decidedBy()));
    }

    @PostMapping("/receipts/{assessmentId}/verify")
    public VerifyReceiptResponse verify(@PathVariable Long assessmentId) {
        var receipt = assessmentService.receiptFor(assessmentId)
                .orElseThrow(() -> new ResourceNotFoundException("no receipt for assessment " + assessmentId));
        boolean valid = signingService.verify(receipt);
        return new VerifyReceiptResponse(valid, receipt.getCommitSha(), receipt.getScanSummaryHash(),
                receipt.getSignerKeyId());
    }

    /** Lets a third party (no AgentShield credentials or DB access) verify a receipt independently. */
    @GetMapping("/signing-key")
    public Map<String, Object> signingKey() {
        return Map.of(
                "algorithm", "Ed25519",
                "keyId", keyProvider.keyId(),
                "publicKeyBase64", keyProvider.publicKeyBase64(),
                "ephemeral", keyProvider.isEphemeral());
    }

    private AssessmentResponse toResponse(CodeAssessment assessment) {
        List<CodeFinding> findings = assessmentService.findingsFor(assessment.getId());
        AiCodeReceipt receipt = assessmentService.receiptFor(assessment.getId()).orElse(null);
        return AssessmentResponse.from(assessment, findings, receipt);
    }
}
