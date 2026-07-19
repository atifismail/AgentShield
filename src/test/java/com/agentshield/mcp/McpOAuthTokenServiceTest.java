package com.agentshield.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.mcp.McpDtos.UpdateMcpAuthRequest;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockOAuthServerController;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * design-mcp-authorization.md §6.5/§11 — token acquisition, claims validation (wrong
 * audience/issuer rejected, never cached), and cache/refresh behavior, against a real (mock)
 * OAuth authorization server rather than mocked HTTP.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpOAuthTokenServiceTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpOAuthTokenService oauthTokenService;
    @Autowired
    private McpOAuthTokenRepository tokenRepository;

    @BeforeEach
    @AfterEach
    void resetMockOAuthServer() {
        MockOAuthServerController.reset();
    }

    private McpServer registerOauthServer(String resource) {
        McpServer server = discoveryService.register(new RegisterMcpServerRequest(
                "oauth-test-server-" + System.nanoTime(), McpTransportType.HTTP,
                "http://localhost:" + port + "/demo/mock-mcp-server", null, null, null, "owner", "DEV", "mcp"));
        String issuer = "http://localhost:" + port + "/demo/mock-oauth-server";
        // Per RFC 8414, the metadata "issuer" field is authoritative and should match both what
        // an operator configures at registration time and what ends up in the token's `iss`
        // claim — the "wrong issuer" test below deliberately breaks this to prove rejection.
        MockOAuthServerController.issuerOverride.set(issuer);
        return discoveryService.updateAuth(server.getId(), new UpdateMcpAuthRequest(McpAuthMode.OAUTH2,
                issuer, resource, null, "test-client", null, null));
    }

    @Test
    void acquiresAndCachesAValidToken() {
        McpServer server = registerOauthServer("http://localhost:" + port + "/demo/mock-mcp-server");

        var result = oauthTokenService.getValidToken(server);

        assertThat(result.success()).isTrue();
        assertThat(result.accessToken()).isNotBlank();
        assertThat(tokenRepository.findByMcpServerId(server.getId())).isPresent();
    }

    @Test
    void rejectsATokenWithTheWrongAudience() {
        McpServer server = registerOauthServer("http://localhost:" + port + "/demo/mock-mcp-server");
        MockOAuthServerController.audienceOverride.set("https://some-other-resource.example.com");

        var result = oauthTokenService.getValidToken(server);

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessage()).contains("aud");
        assertThat(tokenRepository.findByMcpServerId(server.getId())).isEmpty();
    }

    @Test
    void rejectsATokenWithTheWrongIssuer() {
        McpServer server = registerOauthServer("http://localhost:" + port + "/demo/mock-mcp-server");
        // The issuer the mock AS puts in the token no longer matches what was configured at
        // registration time (server.oauthIssuer) — simulates a misconfigured/compromised AS.
        MockOAuthServerController.issuerOverride.set("https://an-impostor-issuer.example.com");

        var result = oauthTokenService.getValidToken(server);

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessage()).contains("iss");
        assertThat(tokenRepository.findByMcpServerId(server.getId())).isEmpty();
    }

    @Test
    void reusesACachedTokenWithoutRefetchingUntilItIsNearExpiry() {
        McpServer server = registerOauthServer("http://localhost:" + port + "/demo/mock-mcp-server");
        var first = oauthTokenService.getValidToken(server);
        assertThat(first.success()).isTrue();

        // Changing the mock AS's audience would make any *new* acquisition fail — a second
        // getValidToken() still succeeding with the identical token proves the cache was used,
        // not a fresh (and here, would-be-rejected) token request.
        MockOAuthServerController.audienceOverride.set("https://would-be-rejected.example.com");

        var second = oauthTokenService.getValidToken(server);

        assertThat(second.success()).isTrue();
        assertThat(second.accessToken()).isEqualTo(first.accessToken());
    }

    @Test
    void refreshesAnExpiredCachedTokenInsteadOfReusingIt() {
        McpServer server = registerOauthServer("http://localhost:" + port + "/demo/mock-mcp-server");
        var first = oauthTokenService.getValidToken(server);
        assertThat(first.success()).isTrue();

        // Force the cached row into the past, as if it had genuinely expired.
        var cached = tokenRepository.findByMcpServerId(server.getId()).orElseThrow();
        cached.setExpiresAt(Instant.now().minusSeconds(60));
        tokenRepository.saveAndFlush(cached);
        // The mock AS's `exp` claim has one-second resolution — force it to mint a
        // distinguishable token even if both acquisitions land in the same wall-clock second.
        MockOAuthServerController.expiresInSeconds.set(7200);

        var second = oauthTokenService.getValidToken(server);

        assertThat(second.success()).isTrue();
        assertThat(second.accessToken()).isNotEqualTo(first.accessToken());
    }
}
