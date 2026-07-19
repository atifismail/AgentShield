package com.agentshield.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.AgentRepository;
import com.agentshield.support.AbstractIntegrationTest;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

/**
 * Regression test: a POST authenticated with HTTP Basic (no session, no CSRF token) must not be
 * rejected. CSRF protection runs before Basic Auth in Spring Security's default filter chain, so
 * without an explicit exemption every Basic-Auth POST/PUT/DELETE got a bogus 401 — this broke
 * curl/CI/API-tool access to any state-changing endpoint entirely.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SecurityConfigIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;

    @Test
    void basicAuthPostDoesNotRequireCsrfToken() {
        TestRestTemplate rest = new TestRestTemplate("admin", "test-only");
        var response = rest.postForEntity("http://localhost:" + port + "/api/agents",
                Map.of("name", "csrf-regression-agent-" + System.nanoTime()), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void anonymousPostToProtectedEndpointIsRejected() {
        String agentName = "should-not-be-created-" + System.nanoTime();
        TestRestTemplate rest = new TestRestTemplate();
        var response = rest.postForEntity("http://localhost:" + port + "/api/agents",
                Map.of("name", agentName), String.class);

        // Anonymous requests get redirected to the login page (form-login entry point) rather
        // than a bare 401/403 — what actually matters is that no agent gets created.
        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.CREATED);
        assertThat(agentRepository.findByName(agentName)).isEmpty();
    }

    @Test
    void anonymousCannotGrantAnMcpConsent() {
        TestRestTemplate rest = new TestRestTemplate();
        var response = rest.postForEntity("http://localhost:" + port + "/api/mcp-consents",
                Map.of("agentId", 1, "mcpServerId", 1), String.class);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.CREATED);
    }

    @Test
    void adminCanListMcpConsents() {
        TestRestTemplate rest = new TestRestTemplate("admin", "test-only");
        var response = rest.getForEntity("http://localhost:" + port + "/api/mcp-consents", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void anonymousCannotSetMcpServerAuthConfig() {
        TestRestTemplate rest = new TestRestTemplate();
        var response = rest.exchange("http://localhost:" + port + "/api/mcp-servers/1/auth",
                org.springframework.http.HttpMethod.PATCH,
                new org.springframework.http.HttpEntity<>(Map.of("authMode", "NONE")), String.class);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.OK);
    }
}
