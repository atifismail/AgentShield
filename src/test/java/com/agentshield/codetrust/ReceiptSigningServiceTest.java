package com.agentshield.codetrust;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.RiskLevel;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Real Ed25519 round-trip against an ephemeral {@link ReceiptSigningKeyProvider} (constructed
 * with blank config so it self-generates a keypair, per its own dev/demo fallback) — no mocking
 * of the crypto itself, since the whole point of this class is that the signature genuinely
 * verifies (or genuinely doesn't) against real data.
 */
class ReceiptSigningServiceTest {

    private final ReceiptSigningKeyProvider keyProvider = new ReceiptSigningKeyProvider("", "", "test-key");
    private final ReceiptSigningService service = new ReceiptSigningService(keyProvider);

    private CodeAssessment assessment(String commitSha) {
        CodeAssessment assessment = new CodeAssessment();
        assessment.setId(1L);
        assessment.setRepo("example/repo");
        assessment.setCommitSha(commitSha);
        assessment.setBranch("main");
        return assessment;
    }

    private CodeFinding finding(RiskLevel severity) {
        CodeFinding finding = new CodeFinding();
        finding.setCategory(FindingCategory.INSECURE_PATTERN);
        finding.setSeverity(severity);
        finding.setFilePath("src/Main.java");
        finding.setLine(42);
        finding.setRuleId("rule-1");
        return finding;
    }

    @Test
    void signThenVerifySucceedsForUnmodifiedReceipt() {
        AiCodeReceipt receipt = service.sign(assessment("abc123"), List.of(finding(RiskLevel.LOW)));

        assertThat(receipt.getAlgorithm()).isEqualTo("Ed25519");
        assertThat(receipt.getSignerKeyId()).isEqualTo("test-key");
        assertThat(service.verify(receipt)).isTrue();
    }

    @Test
    void verifyFailsIfCommitShaIsAlteredAfterSigning() {
        AiCodeReceipt receipt = service.sign(assessment("abc123"), List.of(finding(RiskLevel.LOW)));

        receipt.setCommitSha("tampered-commit-sha");

        assertThat(service.verify(receipt)).isFalse();
    }

    @Test
    void verifyFailsIfScanSummaryHashIsAlteredAfterSigning() {
        AiCodeReceipt receipt = service.sign(assessment("abc123"), List.of(finding(RiskLevel.LOW)));

        receipt.setScanSummaryHash("0".repeat(receipt.getScanSummaryHash().length()));

        assertThat(service.verify(receipt)).isFalse();
    }

    @Test
    void verifyFailsIfSignatureItselfIsAlteredByASingleCharacter() {
        AiCodeReceipt receipt = service.sign(assessment("abc123"), List.of(finding(RiskLevel.LOW)));
        char[] chars = receipt.getSignature().toCharArray();
        chars[0] = chars[0] == 'A' ? 'B' : 'A';
        receipt.setSignature(new String(chars));

        assertThat(service.verify(receipt)).isFalse();
    }

    @Test
    void differentFindingsProduceDifferentScanSummaryHashes() {
        AiCodeReceipt withLowFinding = service.sign(assessment("abc123"), List.of(finding(RiskLevel.LOW)));
        AiCodeReceipt withMediumFinding = service.sign(assessment("abc123"), List.of(finding(RiskLevel.MEDIUM)));

        assertThat(withLowFinding.getScanSummaryHash()).isNotEqualTo(withMediumFinding.getScanSummaryHash());
    }
}
