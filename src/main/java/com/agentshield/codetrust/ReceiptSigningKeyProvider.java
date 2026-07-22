package com.agentshield.codetrust;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Loads (or, outside production, generates) the Ed25519 keypair {@link ReceiptSigningService}
 * signs AI-code-trust receipts with. JDK-native ({@code KeyPairGenerator.getInstance("Ed25519")},
 * available since JDK 15) — no new dependency, and deliberately separate from the Sigstore
 * keyless verifier used elsewhere in this codebase (that one only ever verifies other publishers'
 * signatures; this one is the one place AgentShield signs something itself).
 *
 * <p>If {@code agentshield.codetrust.signing-private-key}/{@code -public-key} are not configured,
 * an ephemeral keypair is generated at startup so the feature still works out of the box in
 * dev/demo/test — but it will not survive a restart (every receipt signed before a restart fails
 * verification after one, since the public key changes). {@link com.agentshield.security.ProductionSafetyChecks}
 * refuses to start with the {@code prod} profile active while this provider is running on an
 * ephemeral key, the same "explicit acknowledgement required" posture as the stdio sandbox and
 * raw-response-encryption gates elsewhere in this codebase.
 */
@Component
public class ReceiptSigningKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(ReceiptSigningKeyProvider.class);

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String keyId;
    private final boolean ephemeral;

    public ReceiptSigningKeyProvider(
            @Value("${agentshield.codetrust.signing-private-key:}") String base64PrivateKey,
            @Value("${agentshield.codetrust.signing-public-key:}") String base64PublicKey,
            @Value("${agentshield.codetrust.signer-key-id:agentshield-default}") String keyId) {
        this.keyId = keyId;
        if (base64PrivateKey != null && !base64PrivateKey.isBlank()
                && base64PublicKey != null && !base64PublicKey.isBlank()) {
            this.privateKey = decodePrivateKey(base64PrivateKey);
            this.publicKey = decodePublicKey(base64PublicKey);
            this.ephemeral = false;
        } else {
            KeyPair generated = generateKeyPair();
            this.privateKey = generated.getPrivate();
            this.publicKey = generated.getPublic();
            this.ephemeral = true;
            log.warn("agentshield.codetrust.signing-private-key/signing-public-key are not configured; "
                    + "generated an EPHEMERAL Ed25519 keypair for this process only. Receipts signed now will "
                    + "fail verification after a restart, since the public key will differ. Do not run with an "
                    + "ephemeral key in production — set both config values explicitly.");
        }
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    public String keyId() {
        return keyId;
    }

    public boolean isEphemeral() {
        return ephemeral;
    }

    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    private static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Ed25519 is not available on this JVM", e);
        }
    }

    private static PrivateKey decodePrivateKey(String base64) {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(
                    "agentshield.codetrust.signing-private-key is not a valid base64-encoded PKCS8 Ed25519 key", e);
        }
    }

    private static PublicKey decodePublicKey(String base64) {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(
                    "agentshield.codetrust.signing-public-key is not a valid base64-encoded X509 Ed25519 key", e);
        }
    }
}
