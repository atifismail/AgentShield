package com.agentshield.mcp;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.gateway.OutboundEndpointValidator;
import com.agentshield.metrics.GatewayMetrics;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Acquires, validates, caches, and refreshes the OAuth 2.1 access token AgentShield uses to call
 * an {@code auth_mode: OAUTH2} MCP server (design-mcp-authorization.md §6). Uses the
 * {@code client_credentials} grant — see §6.1 for why {@code authorization_code} (the MCP spec's
 * primary, browser-redirect flow) doesn't apply to this non-interactive backend service.
 */
@Component
public class McpOAuthTokenService {

    /** Refresh this long before actual expiry, so a call never races a token that's about to lapse. */
    private static final Duration REFRESH_SKEW = Duration.ofSeconds(30);

    private final McpOAuthTokenRepository tokenRepository;
    private final McpServerRepository serverRepository;
    private final McpTokenEncryptor tokenEncryptor;
    private final JwtClaimsReader claimsReader;
    private final OutboundEndpointValidator outboundEndpointValidator;
    private final AuditService auditService;
    private final GatewayMetrics metrics;
    private final Environment environment;
    private final ObjectMapper objectMapper;
    private final RestClient restClient;

    public McpOAuthTokenService(McpOAuthTokenRepository tokenRepository, McpServerRepository serverRepository,
            McpTokenEncryptor tokenEncryptor, JwtClaimsReader claimsReader,
            OutboundEndpointValidator outboundEndpointValidator, AuditService auditService, GatewayMetrics metrics,
            Environment environment, ObjectMapper objectMapper) {
        this.tokenRepository = tokenRepository;
        this.serverRepository = serverRepository;
        this.tokenEncryptor = tokenEncryptor;
        this.claimsReader = claimsReader;
        this.outboundEndpointValidator = outboundEndpointValidator;
        this.auditService = auditService;
        this.metrics = metrics;
        this.environment = environment;
        this.objectMapper = objectMapper;
        HttpClient jdkClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        this.restClient = RestClient.builder().requestFactory(new JdkClientHttpRequestFactory(jdkClient)).build();
    }

    public record TokenResult(boolean success, String accessToken, String errorMessage) {
        static TokenResult success(String token) {
            return new TokenResult(true, token, null);
        }

        static TokenResult failure(String reason) {
            return new TokenResult(false, null, reason);
        }
    }

    /** Returns a valid, freshly-validated-or-cached token, acquiring/refreshing one if needed. */
    public TokenResult getValidToken(McpServer server) {
        Instant now = Instant.now();
        var cached = tokenRepository.findByMcpServerId(server.getId());
        if (cached.isPresent() && now.isBefore(cached.get().getExpiresAt().minus(REFRESH_SKEW))) {
            try {
                return TokenResult.success(tokenEncryptor.decrypt(cached.get().getAccessTokenEncrypted()));
            } catch (Exception e) {
                // Cached ciphertext is unreadable under the current key — most likely
                // agentshield.mcp.oauth-token-encryption-key was rotated since this token was
                // cached (docs/runbooks/key-token-rotation.md). Fail-closed would be the wrong
                // call here (AGENTS.md rule 6 is about policy evaluation, not this): the token
                // itself is just stale/unreadable, not a security decision, so the correct
                // response is to transparently re-acquire a fresh one rather than surface an
                // uncaught exception that would otherwise break every call to this MCP server
                // until an operator noticed and manually intervened.
                audit(server, "mcp.oauth_token_rejected",
                        "cached token could not be decrypted (likely an encryption key rotation); re-acquiring");
                return acquireToken(server);
            }
        }
        return acquireToken(server);
    }

    private TokenResult acquireToken(McpServer server) {
        if (!tokenEncryptor.isConfigured()) {
            String reason = "agentshield.mcp.oauth-token-encryption-key is not configured";
            audit(server, "mcp.oauth_token_rejected", reason);
            return TokenResult.failure(reason);
        }

        String tokenEndpoint = resolveTokenEndpoint(server);
        if (tokenEndpoint == null) {
            String reason = "could not resolve a token endpoint for MCP server '" + server.getName() + "'";
            audit(server, "mcp.oauth_token_rejected", reason);
            return TokenResult.failure(reason);
        }
        var tokenEndpointValidation = outboundEndpointValidator.validate(tokenEndpoint);
        if (!tokenEndpointValidation.allowed()) {
            String reason = "token endpoint blocked by outbound policy: " + tokenEndpointValidation.reason();
            audit(server, "mcp.oauth_token_rejected", reason);
            return TokenResult.failure(reason);
        }

        String clientSecret = server.getOauthClientSecretRef() == null ? null
                : environment.getProperty(server.getOauthClientSecretRef());
        if (server.getOauthClientSecretRef() != null && clientSecret == null) {
            String reason = "oauth_client_secret_ref '" + server.getOauthClientSecretRef()
                    + "' did not resolve to a configured value";
            audit(server, "mcp.oauth_token_rejected", reason);
            return TokenResult.failure(reason);
        }

        try {
            var form = new org.springframework.util.LinkedMultiValueMap<String, String>();
            form.add("grant_type", "client_credentials");
            form.add("client_id", server.getOauthClientId());
            if (clientSecret != null) {
                form.add("client_secret", clientSecret);
            }
            if (server.getOauthResource() != null) {
                form.add("resource", server.getOauthResource());
            }
            if (server.getOauthScopes() != null) {
                form.add("scope", server.getOauthScopes());
            }

            String responseBody = restClient.post().uri(tokenEndpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve().body(String.class);
            JsonNode responseJson = objectMapper.readTree(responseBody);
            String accessToken = responseJson.path("access_token").asText(null);
            if (accessToken == null) {
                String reason = "token endpoint response had no access_token";
                audit(server, "mcp.oauth_token_rejected", reason);
                return TokenResult.failure(reason);
            }

            var validation = validate(server, accessToken, responseJson);
            if (!validation.success()) {
                audit(server, "mcp.oauth_token_rejected", validation.errorMessage());
                return validation;
            }

            cacheToken(server, accessToken, responseJson);
            audit(server, "mcp.oauth_token_acquired", "acquired a new access token for MCP server '"
                    + server.getName() + "'");
            return TokenResult.success(accessToken);
        } catch (Exception e) {
            String reason = "token request failed: " + e.getMessage();
            audit(server, "mcp.oauth_token_rejected", reason);
            return TokenResult.failure(reason);
        }
    }

    /**
     * Claims-only validation (no signature check — see {@link JwtClaimsReader}). Every failure
     * here is exactly what "wrong-audience tokens must be rejected" (design §6.5) requires:
     * discarded, never cached, never used, and audited with the specific reason.
     */
    private TokenResult validate(McpServer server, String accessToken, JsonNode tokenResponse) {
        JsonNode claims = claimsReader.readClaims(accessToken);
        if (claims == null) {
            // Not a JWT AgentShield can inspect (e.g. an opaque token). Trust the direct,
            // TLS-protected response from the configured token endpoint rather than fail closed
            // on a format AgentShield can't parse — the AS itself is the trust boundary here.
            return TokenResult.success(accessToken);
        }

        if (server.getOauthResource() != null && !audienceContains(claims, server.getOauthResource())) {
            return TokenResult.failure("token 'aud' claim does not contain the expected resource '"
                    + server.getOauthResource() + "'");
        }
        if (server.getOauthIssuer() != null && claims.has("iss")
                && !server.getOauthIssuer().equals(claims.path("iss").asText())) {
            return TokenResult.failure("token 'iss' claim '" + claims.path("iss").asText()
                    + "' does not match the configured issuer '" + server.getOauthIssuer() + "'");
        }
        if (claims.has("exp")) {
            Instant exp = Instant.ofEpochSecond(claims.path("exp").asLong());
            if (!exp.isAfter(Instant.now())) {
                return TokenResult.failure("token 'exp' claim is already in the past");
            }
        }
        String requestedScope = server.getOauthScopes();
        String grantedScope = tokenResponse.path("scope").asText(claims.path("scope").asText(null));
        if (requestedScope != null && grantedScope != null && !isScopeSubset(grantedScope, requestedScope)) {
            return TokenResult.failure("token grants scope '" + grantedScope
                    + "' which was not requested ('" + requestedScope + "')");
        }
        return TokenResult.success(accessToken);
    }

    private boolean audienceContains(JsonNode claims, String expectedResource) {
        JsonNode aud = claims.get("aud");
        if (aud == null) {
            return false;
        }
        if (aud.isArray()) {
            for (JsonNode value : aud) {
                if (expectedResource.equals(value.asText())) {
                    return true;
                }
            }
            return false;
        }
        return expectedResource.equals(aud.asText());
    }

    private boolean isScopeSubset(String grantedScope, String requestedScope) {
        List<String> requested = List.of(requestedScope.split("\\s+"));
        for (String granted : grantedScope.split("\\s+")) {
            if (!requested.contains(granted)) {
                return false;
            }
        }
        return true;
    }

    private void cacheToken(McpServer server, String accessToken, JsonNode tokenResponse) {
        long expiresInSeconds = tokenResponse.path("expires_in").asLong(3600);
        McpOAuthToken cached = tokenRepository.findByMcpServerId(server.getId()).orElseGet(McpOAuthToken::new);
        cached.setMcpServer(server);
        cached.setAccessTokenEncrypted(tokenEncryptor.encrypt(accessToken));
        cached.setIssuedAt(Instant.now());
        cached.setExpiresAt(Instant.now().plusSeconds(expiresInSeconds));
        cached.setScope(tokenResponse.path("scope").asText(null));
        tokenRepository.save(cached);
    }

    /**
     * RFC 8414 Authorization Server Metadata discovery, resolved once at first use and cached on
     * the server row. Operators registering an OAuth2 MCP server are expected to configure
     * {@code oauthIssuer} directly (this is an explicit, operator-provisioned relationship, not a
     * general-purpose MCP client doing blind runtime discovery from an arbitrary 401 response —
     * design §6.2 scopes discovery down accordingly).
     */
    private String resolveTokenEndpoint(McpServer server) {
        if (server.getOauthTokenEndpoint() != null) {
            return server.getOauthTokenEndpoint();
        }
        if (server.getOauthIssuer() == null) {
            return null;
        }
        String issuer = server.getOauthIssuer().endsWith("/")
                ? server.getOauthIssuer().substring(0, server.getOauthIssuer().length() - 1)
                : server.getOauthIssuer();
        String metadataUrl = issuer + "/.well-known/oauth-authorization-server";
        var validation = outboundEndpointValidator.validate(metadataUrl);
        if (!validation.allowed()) {
            return null;
        }
        try {
            String body = restClient.get().uri(metadataUrl).retrieve().body(String.class);
            String tokenEndpoint = objectMapper.readTree(body).path("token_endpoint").asText(null);
            if (tokenEndpoint != null) {
                server.setOauthTokenEndpoint(tokenEndpoint);
                serverRepository.save(server);
            }
            return tokenEndpoint;
        } catch (Exception e) {
            return null;
        }
    }

    private void audit(McpServer server, String eventType, String message) {
        boolean rejected = eventType.endsWith("_rejected");
        auditService.record(null, eventType, ActorType.SYSTEM, "mcp-oauth", null, null,
                rejected ? AuditSeverity.WARNING : AuditSeverity.INFO, message, null);
        if (rejected) {
            metrics.mcpOAuthTokenRejected();
        }
    }
}
