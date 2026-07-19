package com.agentshield.mcp;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * AES-256-GCM encryption for cached MCP OAuth access tokens (design-mcp-authorization.md §4).
 * Mirrors {@link com.agentshield.gateway.RawResponseEncryptor} but with its own key property —
 * deliberately separate key material, so a leaked key only affects one blast radius. Unlike raw
 * response retention, this feature is not optional: any MCP server configured with
 * {@code auth_mode: OAUTH2} needs a token cached, so a missing/invalid key fails startup only
 * when at least one such server is configured, not unconditionally.
 */
@Component
public class McpTokenEncryptor {

    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private final SecretKeySpec key;
    private final SecureRandom secureRandom = new SecureRandom();

    public McpTokenEncryptor(@Value("${agentshield.mcp.oauth-token-encryption-key:}") String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            this.key = null;
            return;
        }
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(base64Key);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("agentshield.mcp.oauth-token-encryption-key is not valid base64", e);
        }
        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                    "agentshield.mcp.oauth-token-encryption-key must decode to exactly 32 bytes (AES-256), got "
                            + keyBytes.length);
        }
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    public boolean isConfigured() {
        return key != null;
    }

    public String encrypt(String plaintext) {
        requireConfigured();
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new IllegalStateException("failed to encrypt MCP OAuth token", e);
        }
    }

    public String decrypt(String base64Combined) {
        requireConfigured();
        try {
            byte[] combined = Base64.getDecoder().decode(base64Combined);
            byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_BYTES, combined.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("failed to decrypt MCP OAuth token", e);
        }
    }

    private void requireConfigured() {
        if (key == null) {
            throw new IllegalStateException(
                    "agentshield.mcp.oauth-token-encryption-key is not set but an MCP server requires OAuth2 auth");
        }
    }
}
