package com.agentshield.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A minimal mock OAuth 2.1 authorization server for exercising
 * {@code McpOAuthTokenService}'s discovery/acquisition/validation logic in tests: RFC 8414
 * metadata discovery plus a {@code client_credentials} token endpoint that hands back a JWT with
 * test-controllable claims. AgentShield only decodes these claims (see
 * {@code JwtClaimsReader}) — it never verifies a signature — so the "signature" segment here is
 * a fixed placeholder, not a real one; that's an intentional match to what AgentShield actually
 * checks, not an oversight.
 */
@RestController
@RequestMapping("/demo/mock-oauth-server")
public class MockOAuthServerController {

    /** Null = echo back whatever the client requested as `resource`. */
    public static final AtomicReference<String> audienceOverride = new AtomicReference<>();
    public static final AtomicReference<String> issuerOverride = new AtomicReference<>("https://mock-as.test");
    public static final AtomicLong expiresInSeconds = new AtomicLong(3600);
    /** Null = echo back whatever the client requested as `scope`. */
    public static final AtomicReference<String> scopeOverride = new AtomicReference<>();

    private final ObjectMapper objectMapper = new ObjectMapper();

    public static void reset() {
        audienceOverride.set(null);
        issuerOverride.set("https://mock-as.test");
        expiresInSeconds.set(3600);
        scopeOverride.set(null);
    }

    @GetMapping("/.well-known/oauth-authorization-server")
    public ObjectNode metadata(HttpServletRequest request) {
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("issuer", issuerOverride.get());
        String base = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
        metadata.put("token_endpoint", base + "/demo/mock-oauth-server/token");
        return metadata;
    }

    @PostMapping(value = "/token", consumes = "application/x-www-form-urlencoded")
    public ObjectNode token(@RequestParam(required = false) String resource, @RequestParam(required = false) String scope) {
        String audience = audienceOverride.get() != null ? audienceOverride.get() : resource;
        String grantedScope = scopeOverride.get() != null ? scopeOverride.get() : scope;

        ObjectNode claims = objectMapper.createObjectNode();
        claims.put("aud", audience);
        claims.put("iss", issuerOverride.get());
        claims.put("exp", Instant.now().plusSeconds(expiresInSeconds.get()).getEpochSecond());
        if (grantedScope != null) {
            claims.put("scope", grantedScope);
        }

        String header = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = base64Url(claims.toString());
        String token = header + "." + payload + "." + base64Url("test-signature-not-verified");

        ObjectNode response = objectMapper.createObjectNode();
        response.put("access_token", token);
        response.put("token_type", "Bearer");
        response.put("expires_in", expiresInSeconds.get());
        if (grantedScope != null) {
            response.put("scope", grantedScope);
        }
        return response;
    }

    private String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
