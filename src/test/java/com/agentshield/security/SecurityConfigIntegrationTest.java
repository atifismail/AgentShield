package com.agentshield.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.AgentRepository;
import com.agentshield.support.AbstractIntegrationTest;
import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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

    /**
     * Regression test for the admin UI's actual browser flow: form-login (session cookie), then
     * an AJAX POST that reads the raw XSRF-TOKEN cookie and echoes it in an X-XSRF-TOKEN header
     * (exactly what static/js/app.js does before every state-changing request). Spring Security
     * 6's default CsrfTokenRequestHandler (XorCsrfTokenRequestAttributeHandler) BREACH-masks the
     * token it expects back, which never matches a raw cookie value read directly by JS — so
     * without SecurityConfig explicitly installing the plain CsrfTokenRequestAttributeHandler,
     * every AJAX action in the admin UI (register/approve/reject buttons, DLP profile forms, etc.)
     * would 403 unconditionally regardless of a valid session and role. The existing
     * {@link #basicAuthPostDoesNotRequireCsrfToken()} test doesn't cover this because Basic Auth
     * is CSRF-exempt entirely -- this is the one test that actually exercises the cookie/header
     * path the UI depends on.
     */
    @Test
    void sessionAuthenticatedAjaxPostSucceedsWithCookieEchoedCsrfToken() throws Exception {
        CookieManager cookieManager = new CookieManager();
        HttpClient client = HttpClient.newBuilder().cookieHandler(cookieManager)
                .followRedirects(HttpClient.Redirect.NORMAL).build();
        String base = "http://localhost:" + port;

        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(URI.create(base + "/login")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        Matcher csrfMatcher = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"").matcher(loginPage.body());
        assertThat(csrfMatcher.find()).as("login page must render a CSRF hidden field").isTrue();
        String loginCsrf = csrfMatcher.group(1);

        String form = "username=admin&password=test-only&_csrf=" + loginCsrf;
        client.send(HttpRequest.newBuilder(URI.create(base + "/login"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form)).build(),
                HttpResponse.BodyHandlers.discarding());

        // A second GET, like a browser navigating to a page after login, so a current
        // XSRF-TOKEN cookie tied to the now-authenticated session is available to read -- read
        // from the cookie jar itself (like a browser would), not one specific response's
        // Set-Cookie header, since which exact request triggers the CSRF filter to (re-)issue the
        // cookie is an implementation detail this test shouldn't need to know.
        client.send(HttpRequest.newBuilder(URI.create(base + "/tools")).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        String xsrfCookie = cookieManager.getCookieStore().getCookies().stream()
                .filter(cookie -> cookie.getName().equals("XSRF-TOKEN"))
                .map(java.net.HttpCookie::getValue)
                .findFirst()
                .orElse(null);
        assertThat(xsrfCookie).as("XSRF-TOKEN cookie must be set after authenticating").isNotBlank();

        String agentName = "csrf-cookie-ajax-agent-" + System.nanoTime();
        HttpResponse<String> createResponse = client.send(HttpRequest.newBuilder(URI.create(base + "/api/agents"))
                        .header("Content-Type", "application/json")
                        .header("X-XSRF-TOKEN", xsrfCookie)
                        .POST(HttpRequest.BodyPublishers.ofString("{\"name\":\"" + agentName + "\"}")).build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(createResponse.statusCode()).isEqualTo(201);
        assertThat(agentRepository.findByName(agentName)).isPresent();
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
