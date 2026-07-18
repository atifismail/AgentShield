package com.agentshield;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AgentShieldApplicationTests extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Test
    void contextLoads() {
    }

    @Test
    void dashboardPageRendersForAuthenticatedAdmin() {
        TestRestTemplate rest = new TestRestTemplate("admin", "test-only");
        var response = rest.getForEntity("http://localhost:" + port + "/dashboard", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Dashboard");
    }

    @Test
    void dashboardRedirectsAnonymousUserToLogin() {
        TestRestTemplate rest = new TestRestTemplate();
        var response = rest.getForEntity("http://localhost:" + port + "/dashboard", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Sign in");
    }

    @Test
    void healthEndpointIsUp() {
        TestRestTemplate rest = new TestRestTemplate();
        var response = rest.getForEntity("http://localhost:" + port + "/actuator/health", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("UP");
    }
}
