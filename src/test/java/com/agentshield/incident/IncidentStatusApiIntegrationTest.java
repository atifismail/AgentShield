package com.agentshield.incident;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.AuditSeverity;
import com.agentshield.common.IncidentStatus;
import com.agentshield.support.AbstractIntegrationTest;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IncidentStatusApiIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private IncidentRepository incidentRepository;

    private Incident createIncident() {
        Incident incident = new Incident();
        incident.setTitle("test incident " + System.nanoTime());
        incident.setSeverity(AuditSeverity.CRITICAL);
        incident.setStatus(IncidentStatus.OPEN);
        incident.setSummary("summary");
        return incidentRepository.save(incident);
    }

    @Test
    void adminCanTransitionIncidentThroughWorkflowStates() {
        Incident incident = createIncident();
        TestRestTemplate rest = new TestRestTemplate("admin", "test-only");

        var response = rest.exchange("http://localhost:" + port + "/api/incidents/" + incident.getId() + "/status",
                HttpMethod.PATCH, new HttpEntity<>(Map.of("status", "ACKNOWLEDGED")), Incident.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getStatus()).isEqualTo(IncidentStatus.ACKNOWLEDGED);
        assertThat(incidentRepository.findById(incident.getId()).orElseThrow().getStatus())
                .isEqualTo(IncidentStatus.ACKNOWLEDGED);
    }

    @Test
    void anonymousCannotTransitionIncidentStatus() {
        Incident incident = createIncident();
        TestRestTemplate rest = new TestRestTemplate();

        var response = rest.exchange("http://localhost:" + port + "/api/incidents/" + incident.getId() + "/status",
                HttpMethod.PATCH, new HttpEntity<>(Map.of("status", "RESOLVED")), String.class);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.OK);
        assertThat(incidentRepository.findById(incident.getId()).orElseThrow().getStatus())
                .isEqualTo(IncidentStatus.OPEN);
    }
}
