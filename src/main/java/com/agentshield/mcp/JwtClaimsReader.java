package com.agentshield.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * Decodes (never cryptographically verifies) the claims of a JWT access token
 * (design-mcp-authorization.md §6.5). Signature verification is deliberately out of scope here:
 * AgentShield receives this token directly from the MCP server's token endpoint over TLS, as the
 * OAuth client that requested it — the trust boundary is the TLS channel to the authorization
 * server AgentShield itself discovered and configured, not a signature over a token relayed by
 * some other, less-trusted party. What's checked instead is that the claims — audience, issuer,
 * expiry, scope — actually say what AgentShield expects, since a misconfigured or compromised AS
 * could still hand back a token for the wrong resource.
 */
@Component
public class JwtClaimsReader {

    private final ObjectMapper objectMapper;

    public JwtClaimsReader(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /** Returns null if the token isn't a parseable three-segment JWT. */
    public JsonNode readClaims(String token) {
        if (token == null) {
            return null;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return null;
        }
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            return objectMapper.readTree(new String(payload, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }
}
