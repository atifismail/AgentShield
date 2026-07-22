package com.agentshield.codetrust;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.codetrust.CodeTrustDtos.AssessmentResponse;
import com.agentshield.codetrust.CodeTrustDtos.SubmitAssessmentRequest;
import com.agentshield.codetrust.CodeTrustDtos.VerifyReceiptResponse;
import com.agentshield.support.AbstractIntegrationTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * A receipt row mutated directly at the storage layer (bypassing the signing service entirely —
 * simulating a compromised database or an operator hand-editing a row) must fail verification.
 * Mirrors the negative-security-test style of {@code ApprovalConcurrencyIntegrationTest} /
 * {@code ToolRegistrationSecurityTest}: a real attack-shaped scenario, not just a code-coverage
 * exercise.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CodeTrustReceiptTamperSecurityTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AiCodeReceiptRepository receiptRepository;

    private TestRestTemplate authenticatedRest() {
        return new TestRestTemplate().withBasicAuth("admin", "test-only");
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private Long submitPassingAssessment() {
        var submitRequest = new SubmitAssessmentRequest("example/repo", "commit-" + System.nanoTime(), "main",
                "dev@example.com", AssessmentSource.CI, false, "dev@example.com", List.of());
        var response = authenticatedRest().postForEntity(url("/api/codetrust/assessments"), submitRequest,
                AssessmentResponse.class);
        assertThat(response.getBody().status()).isEqualTo(AssessmentStatus.PASSED);
        return response.getBody().id();
    }

    @Test
    void tamperedCommitShaOnStoredReceiptFailsVerification() {
        Long assessmentId = submitPassingAssessment();

        AiCodeReceipt receipt = receiptRepository.findByAssessmentId(assessmentId).orElseThrow();
        receipt.setCommitSha("attacker-supplied-commit-sha");
        receiptRepository.save(receipt);

        var verifyResponse = authenticatedRest().postForEntity(url("/api/codetrust/receipts/" + assessmentId + "/verify"),
                null, VerifyReceiptResponse.class);
        assertThat(verifyResponse.getBody().valid()).isFalse();
    }

    @Test
    void tamperedSignatureOnStoredReceiptFailsVerification() {
        Long assessmentId = submitPassingAssessment();

        AiCodeReceipt receipt = receiptRepository.findByAssessmentId(assessmentId).orElseThrow();
        String signature = receipt.getSignature();
        char[] chars = signature.toCharArray();
        chars[chars.length - 2] = chars[chars.length - 2] == 'A' ? 'B' : 'A';
        receipt.setSignature(new String(chars));
        receiptRepository.save(receipt);

        var verifyResponse = authenticatedRest().postForEntity(url("/api/codetrust/receipts/" + assessmentId + "/verify"),
                null, VerifyReceiptResponse.class);
        assertThat(verifyResponse.getBody().valid()).isFalse();
    }
}
