package com.agentshield.siem.validation;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.support.AbstractIntegrationTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * End-to-end coverage for the alert-import validator and its report rendering: imports a fixture
 * alert export against the default manifest, confirms matched/missed/unexpected classification,
 * and confirms the HTML report renders without error and without leaking anything beyond alert
 * names that were already present in the (here, non-secret) import payload.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SocValidationIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    private TestRestTemplate admin() {
        return new TestRestTemplate().withBasicAuth("admin", "test-only");
    }

    @Test
    void importingAFixtureAlertExportClassifiesMatchedMissedAndUnexpected() {
        String body = """
                {
                  "alerts": [
                    {"alertName": "AgentShield Tool Schema Drift", "ruleId": "r1", "timestamp": "2026-01-01T00:00:00Z", "sourceEvent": "evt-1"},
                    {"alertName": "Completely Unrelated Alert", "ruleId": "r99", "timestamp": "2026-01-01T00:00:00Z", "sourceEvent": "evt-99"}
                  ]
                }
                """;
        HttpEntity<String> request = jsonRequest(body);

        ResponseEntity<SocValidationDtos.ImportAlertsResponse> response = admin().postForEntity(
                "http://localhost:" + port + "/api/siem/validation/alerts/import", request,
                SocValidationDtos.ImportAlertsResponse.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        var result = response.getBody();
        assertThat(result).isNotNull();
        assertThat(result.matchedScenarios()).contains("scenario-1");
        assertThat(result.unexpectedAlertNames()).contains("Completely Unrelated Alert");
        assertThat(result.missedScenarios()).isNotEmpty();
        assertThat(result.validationRunId()).isNotNull();
    }

    @Test
    void htmlReportRendersWithoutErrorAndEscapesImportedContent() {
        String body = """
                {
                  "alerts": [
                    {"alertName": "<script>alert(1)</script>", "ruleId": "r1", "timestamp": "2026-01-01T00:00:00Z", "sourceEvent": "evt-1"}
                  ]
                }
                """;
        HttpEntity<String> request = jsonRequest(body);
        ResponseEntity<SocValidationDtos.ImportAlertsResponse> importResponse = admin().postForEntity(
                "http://localhost:" + port + "/api/siem/validation/alerts/import", request,
                SocValidationDtos.ImportAlertsResponse.class);
        Long runId = importResponse.getBody().validationRunId();

        ResponseEntity<String> reportResponse = admin().getForEntity(
                "http://localhost:" + port + "/api/siem/validation/runs/" + runId + "/report?format=html",
                String.class);

        assertThat(reportResponse.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(reportResponse.getBody()).contains("SOC Validation Report");
        // The imported alert name containing a raw <script> tag must be HTML-escaped in the report.
        assertThat(reportResponse.getBody()).doesNotContain("<script>alert(1)</script>");
    }

    @Test
    void markdownReportIsTheDefaultFormat() {
        String body = """
                {"alerts": [{"alertName": "AgentShield Tool Schema Drift", "ruleId": "r1", "timestamp": "2026-01-01T00:00:00Z", "sourceEvent": "evt-1"}]}
                """;
        HttpEntity<String> request = jsonRequest(body);
        ResponseEntity<SocValidationDtos.ImportAlertsResponse> importResponse = admin().postForEntity(
                "http://localhost:" + port + "/api/siem/validation/alerts/import", request,
                SocValidationDtos.ImportAlertsResponse.class);
        Long runId = importResponse.getBody().validationRunId();

        ResponseEntity<String> reportResponse = admin().getForEntity(
                "http://localhost:" + port + "/api/siem/validation/runs/" + runId + "/report", String.class);

        assertThat(reportResponse.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(reportResponse.getBody()).contains("# SOC Validation Report");
    }

    private HttpEntity<String> jsonRequest(String body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new HttpEntity<>(body, headers);
    }
}
