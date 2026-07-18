package com.agentshield.gateway;

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
 * AES-256-GCM encryption for the optional raw-tool-response retention feature
 * (improvement_plan.md #7). Off by default — {@code agentshield.audit.retain-raw-tool-responses}
 * must be explicitly enabled, and doing so without a valid 32-byte base64
 * {@code agentshield.audit.raw-response-encryption-key} fails startup rather than silently
 * storing plaintext or a weak key.
 */
@Component
public class RawResponseEncryptor {

    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private final boolean enabled;
    private final SecretKeySpec key;
    private final SecureRandom secureRandom = new SecureRandom();

    public RawResponseEncryptor(
            @Value("${agentshield.audit.retain-raw-tool-responses:false}") boolean enabled,
            @Value("${agentshield.audit.raw-response-encryption-key:}") String base64Key) {
        this.enabled = enabled;
        if (!enabled) {
            this.key = null;
            return;
        }
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException("agentshield.audit.retain-raw-tool-responses is enabled but "
                    + "agentshield.audit.raw-response-encryption-key is not set");
        }
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(base64Key);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("agentshield.audit.raw-response-encryption-key is not valid base64", e);
        }
        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                    "agentshield.audit.raw-response-encryption-key must decode to exactly 32 bytes (AES-256), got "
                            + keyBytes.length);
        }
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String encrypt(String plaintext) {
        if (!enabled || plaintext == null) {
            return null;
        }
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
            throw new IllegalStateException("failed to encrypt raw tool response", e);
        }
    }

    public String decrypt(String base64Combined) {
        if (!enabled || base64Combined == null) {
            return null;
        }
        try {
            byte[] combined = Base64.getDecoder().decode(base64Combined);
            byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_BYTES, combined.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("failed to decrypt raw tool response", e);
        }
    }
}
