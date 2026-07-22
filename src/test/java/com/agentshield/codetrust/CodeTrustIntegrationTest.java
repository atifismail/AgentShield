package com.agentshield.codetrust;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.codetrust.CodeTrustDtos.AssessmentResponse;
import com.agentshield.codetrust.CodeTrustDtos.FindingRequest;
import com.agentshield.codetrust.CodeTrustDtos.ReviewDecisionRequest;
import com.agentshield.codetrust.CodeTrustDtos.SubmitAssessmentRequest;
import com.agentshield.codetrust.CodeTrustDtos.VerifyReceiptResponse;
import com.agentshield.common.RiskLevel;
import com.agentshield.support.AbstractIntegrationTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

/**
 * End-to-end: submit an assessment with a HIGH secret finding (BLOCKED, no receipt) -> a
 * SECURITY_ANALYST-equivalent operator approves it -> it PASSES and a receipt is issued -> the
 * receipt verifies. Uses the real signing key (ephemeral in the test profile, see
 * ReceiptSigningKeyProvider) end to end, no mocking.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CodeTrustIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    private TestRestTemplate authenticatedRest() {
        // src/test/resources/application-test.yml overrides the default admin password to
        // "test-only" (not the "changeit" application.yml default) specifically for tests.
        return new TestRestTemplate().withBasicAuth("admin", "test-only");
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void submitBlockedApproveThenReceiptVerifies() {
        var submitRequest = new SubmitAssessmentRequest("example/repo", "commit-" + System.nanoTime(), "main",
                "dev@example.com", AssessmentSource.CLI, false, "dev@example.com",
                List.of(new FindingRequest("src/Config.java", 12, FindingCategory.SECRET, RiskLevel.CRITICAL,
                        "planted-secret", "hardcoded API key")));

        var submitResponse = authenticatedRest().postForEntity(url("/api/codetrust/assessments"), submitRequest,
                AssessmentResponse.class);
        assertThat(submitResponse.getStatusCode().value()).isEqualTo(201);
        Long id = submitResponse.getBody().id();
        assertThat(submitResponse.getBody().status()).isEqualTo(AssessmentStatus.BLOCKED);
        assertThat(submitResponse.getBody().receipt()).isNull();

        var approveResponse = authenticatedRest().postForEntity(url("/api/codetrust/assessments/" + id + "/approve"),
                new ReviewDecisionRequest("security-analyst-1"), AssessmentResponse.class);
        assertThat(approveResponse.getBody().status()).isEqualTo(AssessmentStatus.PASSED);
        assertThat(approveResponse.getBody().approvedBy()).isEqualTo("security-analyst-1");
        assertThat(approveResponse.getBody().receipt()).isNotNull();

        var verifyResponse = authenticatedRest().postForEntity(url("/api/codetrust/receipts/" + id + "/verify"), null,
                VerifyReceiptResponse.class);
        assertThat(verifyResponse.getBody().valid()).isTrue();
    }

    @Test
    void submitWithNoBlockingFindingsPassesImmediatelyAndReceiptVerifies() {
        var submitRequest = new SubmitAssessmentRequest("example/repo", "commit-" + System.nanoTime(), "main",
                "dev@example.com", AssessmentSource.CI, false, "dev@example.com", List.of());

        var submitResponse = authenticatedRest().postForEntity(url("/api/codetrust/assessments"), submitRequest,
                AssessmentResponse.class);

        assertThat(submitResponse.getBody().status()).isEqualTo(AssessmentStatus.PASSED);
        assertThat(submitResponse.getBody().receipt()).isNotNull();

        var verifyResponse = authenticatedRest().postForEntity(
                url("/api/codetrust/receipts/" + submitResponse.getBody().id() + "/verify"), null,
                VerifyReceiptResponse.class);
        assertThat(verifyResponse.getBody().valid()).isTrue();
    }

    @Test
    void submitFlaggedAsRequiringRescanStaysPendingWithNoReceipt() {
        var submitRequest = new SubmitAssessmentRequest("example/repo", "commit-" + System.nanoTime(), "main",
                "dev@example.com", AssessmentSource.CLI, true, "dev@example.com", List.of());

        var submitResponse = authenticatedRest().postForEntity(url("/api/codetrust/assessments"), submitRequest,
                AssessmentResponse.class);

        assertThat(submitResponse.getBody().status()).isEqualTo(AssessmentStatus.PENDING);
        assertThat(submitResponse.getBody().receipt()).isNull();
    }

    @Test
    void submissionWithoutCredentialsIsUnauthorized() {
        var headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        var submitRequest = new SubmitAssessmentRequest("example/repo", "commit-x", "main", "dev@example.com",
                AssessmentSource.CLI, false, "dev@example.com", List.of());
        var entity = new HttpEntity<>(submitRequest, headers);

        var response = new TestRestTemplate().exchange(url("/api/codetrust/assessments"), HttpMethod.POST, entity,
                String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }
}
