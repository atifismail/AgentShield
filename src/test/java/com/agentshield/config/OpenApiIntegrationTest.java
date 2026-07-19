package com.agentshield.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

/**
 * improvement_plan.md #13 acceptance: "Local /swagger-ui.html works." The test profile doesn't
 * activate "prod", so springdoc stays enabled here — the prod-disabled half of the acceptance
 * criterion is verified live via docker-compose with SPRING_PROFILES_ACTIVE=prod, since spinning
 * up a full "prod" Spring context in-process would also need to satisfy ProductionSafetyChecks
 * (real admin password, TLS-only session cookies, etc.) unrelated to this feature.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OpenApiIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    private final TestRestTemplate rest = new TestRestTemplate();

    @Test
    void swaggerUiIsReachableWithoutAuthentication() {
        var response = rest.getForEntity("http://localhost:" + port + "/swagger-ui.html", String.class);

        assertThat(response.getStatusCode()).isIn(HttpStatus.OK, HttpStatus.FOUND);
    }

    @Test
    void apiDocsExposeTheDocumentedTags() {
        var response = rest.getForEntity("http://localhost:" + port + "/v3/api-docs", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"Gateway\"");
        assertThat(response.getBody()).contains("\"Agents\"");
        assertThat(response.getBody()).contains("\"Tools\"");
        assertThat(response.getBody()).contains("\"Approvals\"");
        assertThat(response.getBody()).contains("\"Audit\"");
        assertThat(response.getBody()).contains("\"Incidents\"");
        assertThat(response.getBody()).contains("/api/gateway/invoke");
    }
}
