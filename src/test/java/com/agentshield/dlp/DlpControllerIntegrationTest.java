package com.agentshield.dlp;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.dlp.DlpDtos.RagScanRequest;
import com.agentshield.dlp.DlpDtos.RagScanResponse;
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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DlpControllerIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    private TestRestTemplate authenticatedRest() {
        // src/test/resources/application-test.yml overrides the default admin password to
        // "test-only" (not the "changeit" application.yml default) specifically for tests.
        return new TestRestTemplate().withBasicAuth("admin", "test-only");
    }

    @Test
    void ragScanClassifiesPlantedSecretAndNeverEchoesItBack() {
        var request = new RagScanRequest("customer record: password=hunter2-actual-secret-value", "doc-1");

        var response = authenticatedRest().postForEntity("http://localhost:" + port + "/api/dlp/rag/scan", request,
                RagScanResponse.class);

        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().action()).isEqualTo(DlpAction.BLOCK);
        assertThat(response.getBody().blocked()).isTrue();
        assertThat(response.getBody().findings()).isNotEmpty();
        assertThat(response.getBody().findings().stream().map(f -> f.category()))
                .contains("CREDENTIAL");
        // The response body as a whole (findings + any redactedText) must never contain the raw
        // matched secret, same discipline as the gateway's response-scanning path.
        assertThat(response.getBody().toString()).doesNotContain("hunter2-actual-secret-value");
    }

    @Test
    void ragScanOnOrdinaryTextReturnsAllowWithNoFindings() {
        var request = new RagScanRequest("the quarterly summary was filed on schedule", "doc-2");

        var response = authenticatedRest().postForEntity("http://localhost:" + port + "/api/dlp/rag/scan", request,
                RagScanResponse.class);

        assertThat(response.getBody().action()).isEqualTo(DlpAction.ALLOW);
        assertThat(response.getBody().blocked()).isFalse();
        assertThat(response.getBody().findings()).isEqualTo(List.of());
    }

    @Test
    void ragScanWithoutCredentialsIsUnauthorized() {
        // An explicit "Accept: application/json" is required here so Spring Security's content
        // negotiation picks the Basic-Auth entry point (401) rather than redirecting an API-style
        // request to the browser /login page the way it would for a plain Accept: */*.
        var headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        var entity = new HttpEntity<>(new RagScanRequest("irrelevant text", "doc-3"), headers);

        var response = new TestRestTemplate().exchange("http://localhost:" + port + "/api/dlp/rag/scan",
                HttpMethod.POST, entity, String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }
}
