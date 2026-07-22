package com.agentshield.codetrust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.audit.AuditService;
import com.agentshield.codetrust.CodeTrustDtos.FindingRequest;
import com.agentshield.codetrust.CodeTrustDtos.SubmitAssessmentRequest;
import com.agentshield.common.ConflictException;
import com.agentshield.common.RiskLevel;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class CodeAssessmentServiceTest {

    private final CodeAssessmentRepository assessmentRepository = Mockito.mock(CodeAssessmentRepository.class);
    private final CodeFindingRepository findingRepository = Mockito.mock(CodeFindingRepository.class);
    private final AiCodeReceiptRepository receiptRepository = Mockito.mock(AiCodeReceiptRepository.class);
    private final ReceiptSigningService signingService = Mockito.mock(ReceiptSigningService.class);
    private final AuditService auditService = Mockito.mock(AuditService.class);
    private final CodeAssessmentService service = new CodeAssessmentService(assessmentRepository, findingRepository,
            receiptRepository, signingService, auditService);

    private SubmitAssessmentRequest request(boolean requiresRescan, List<FindingRequest> findings) {
        return new SubmitAssessmentRequest("example/repo", "abc123", "main", "dev@example.com",
                AssessmentSource.CLI, requiresRescan, "dev@example.com", findings);
    }

    private FindingRequest finding(RiskLevel severity) {
        return new FindingRequest("src/Main.java", 10, FindingCategory.SECRET, severity, "rule-1", "planted secret");
    }

    private void mockSaveIdentity() {
        Mockito.when(assessmentRepository.save(Mockito.any())).thenAnswer(inv -> inv.getArgument(0));
        Mockito.when(findingRepository.save(Mockito.any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void submitWithNoBlockingFindingsPassesAndIssuesReceipt() {
        mockSaveIdentity();
        Mockito.when(signingService.sign(Mockito.any(), Mockito.anyList())).thenReturn(new AiCodeReceipt());

        CodeAssessment result = service.submit(request(false, List.of(finding(RiskLevel.LOW))));

        assertThat(result.getStatus()).isEqualTo(AssessmentStatus.PASSED);
        Mockito.verify(signingService).sign(Mockito.eq(result), Mockito.anyList());
        Mockito.verify(receiptRepository).save(Mockito.any());
    }

    @Test
    void submitWithCriticalFindingBlocksAndIssuesNoReceipt() {
        mockSaveIdentity();

        CodeAssessment result = service.submit(request(false, List.of(finding(RiskLevel.CRITICAL))));

        assertThat(result.getStatus()).isEqualTo(AssessmentStatus.BLOCKED);
        Mockito.verifyNoInteractions(signingService);
        Mockito.verify(receiptRepository, Mockito.never()).save(Mockito.any());
    }

    @Test
    void submitWithHighFindingBlocks() {
        mockSaveIdentity();

        CodeAssessment result = service.submit(request(false, List.of(finding(RiskLevel.HIGH))));

        assertThat(result.getStatus()).isEqualTo(AssessmentStatus.BLOCKED);
    }

    @Test
    void submitFlaggedAsRequiringRescanStaysPendingEvenWithNoBlockingFindings() {
        mockSaveIdentity();

        CodeAssessment result = service.submit(request(true, List.of()));

        assertThat(result.getStatus()).isEqualTo(AssessmentStatus.PENDING);
        Mockito.verifyNoInteractions(signingService);
    }

    @Test
    void approvingANonBlockedAssessmentThrowsConflict() {
        CodeAssessment passed = new CodeAssessment();
        passed.setId(5L);
        passed.setStatus(AssessmentStatus.PASSED);
        Mockito.when(assessmentRepository.findByIdForUpdate(5L)).thenReturn(Optional.of(passed));

        assertThatThrownBy(() -> service.approve(5L, "analyst"))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void approvingABlockedAssessmentPassesItAndIssuesAReceipt() {
        CodeAssessment blocked = new CodeAssessment();
        blocked.setId(6L);
        blocked.setStatus(AssessmentStatus.BLOCKED);
        Mockito.when(assessmentRepository.findByIdForUpdate(6L)).thenReturn(Optional.of(blocked));
        Mockito.when(assessmentRepository.save(Mockito.any())).thenAnswer(inv -> inv.getArgument(0));
        Mockito.when(findingRepository.findByAssessmentId(6L)).thenReturn(List.of());
        Mockito.when(signingService.sign(Mockito.any(), Mockito.anyList())).thenReturn(new AiCodeReceipt());

        CodeAssessment result = service.approve(6L, "analyst");

        assertThat(result.getStatus()).isEqualTo(AssessmentStatus.PASSED);
        assertThat(result.getApprovedBy()).isEqualTo("analyst");
        Mockito.verify(receiptRepository).save(Mockito.any());
    }

    @Test
    void rejectingABlockedAssessmentLeavesItBlockedWithNoReceipt() {
        CodeAssessment blocked = new CodeAssessment();
        blocked.setId(7L);
        blocked.setStatus(AssessmentStatus.BLOCKED);
        Mockito.when(assessmentRepository.findByIdForUpdate(7L)).thenReturn(Optional.of(blocked));
        Mockito.when(assessmentRepository.save(Mockito.any())).thenAnswer(inv -> inv.getArgument(0));

        CodeAssessment result = service.reject(7L, "analyst");

        assertThat(result.getStatus()).isEqualTo(AssessmentStatus.BLOCKED);
        assertThat(result.getRejectedBy()).isEqualTo("analyst");
        Mockito.verifyNoInteractions(signingService);
    }
}
