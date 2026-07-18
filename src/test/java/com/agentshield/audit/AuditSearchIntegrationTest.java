package com.agentshield.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.support.AbstractIntegrationTest;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

/**
 * Regression test: /api/audit?since=... previously used a JPQL "(:since is null or ...)"
 * pattern that PostgreSQL's driver could not infer a parameter type for (fails with
 * "could not determine data type of parameter"). Now backed by a Specification instead.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditSearchIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AuditService auditService;

    @Test
    void searchWithSinceFilterSucceeds() {
        auditService.record(null, "test.event", ActorType.SYSTEM, "tester", null, null, AuditSeverity.INFO,
                "regression test event", null);

        TestRestTemplate rest = new TestRestTemplate("admin", "test-only");
        String url = "http://localhost:" + port + "/api/audit?since=" + Instant.now().minusSeconds(3600);
        var response = rest.getForEntity(url, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void searchWithAllFiltersSucceeds() {
        TestRestTemplate rest = new TestRestTemplate("admin", "test-only");
        String url = "http://localhost:" + port + "/api/audit?agentId=1&toolId=1&severity=INFO&since="
                + Instant.now().minusSeconds(3600);
        var response = rest.getForEntity(url, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
