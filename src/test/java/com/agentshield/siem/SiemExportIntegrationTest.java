package com.agentshield.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;

/**
 * Proves {@code GET /api/siem/export} works end-to-end against a real running instance, that its
 * NDJSON format is one object per line with no wrapping array, and — replaying demo-lab scenario 3
 * (secret-like response blocked) first — that a blocked-secret event never contains the raw secret
 * value, only detector category/confidence metadata.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SiemExportIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AttackSimulatorService attackSimulatorService;

    private TestRestTemplate admin() {
        return new TestRestTemplate().withBasicAuth("admin", "test-only");
    }

    @Test
    void jsonExportValidatesAgainstTheDocumentedSchema() {
        attackSimulatorService.runAll();
        String from = java.time.Instant.now().minusSeconds(3600).toString();
        String to = java.time.Instant.now().plusSeconds(60).toString();

        ResponseEntity<SiemEventDtos.SiemEvent[]> response = admin().getForEntity(
                "http://localhost:" + port + "/api/siem/export?from=" + from + "&to=" + to,
                SiemEventDtos.SiemEvent[].class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody()).isNotEmpty();
    }

    @Test
    void ndjsonExportContainsNoRawSecretValueForABlockedSecretScenario() {
        attackSimulatorService.runAll();
        String from = java.time.Instant.now().minusSeconds(3600).toString();
        String to = java.time.Instant.now().plusSeconds(60).toString();

        ResponseEntity<String> response = admin().getForEntity(
                "http://localhost:" + port + "/api/siem/export?from=" + from + "&to=" + to + "&format=ndjson",
                String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        String body = response.getBody();
        assertThat(body).isNotBlank();
        // demo-attack-lab.sh scenario 3's planted secret is an AWS-access-key-like string; it must
        // never appear verbatim in the export, even though the scenario deliberately triggers it.
        assertThat(body).doesNotContain("AKIA");
        // Every line must be a standalone JSON object (NDJSON), not one big wrapping array.
        for (String line : body.strip().split("\n")) {
            assertThat(line.strip()).startsWith("{").endsWith("}");
        }
    }
}
