package com.agentshield.tool;

import dev.sigstore.KeylessVerificationException;
import dev.sigstore.KeylessVerifier;
import dev.sigstore.VerificationOptions;
import dev.sigstore.bundle.Bundle;
import dev.sigstore.strings.StringMatcher;
import java.io.StringReader;
import org.springframework.stereotype.Component;

/**
 * Real Sigstore-backed implementation of {@link SignatureVerifier}, using
 * {@code dev.sigstore:sigstore-java}'s {@code KeylessVerifier} in-process — never the
 * {@code cosign} CLI (design-tool-supply-chain-provenance.md §5.2). Checks (via the library):
 * signature validity over the artifact digest, certificate chain to Sigstore's public root of
 * trust, the signing certificate's embedded OIDC identity/issuer against what's expected, and
 * Rekor transparency-log inclusion (carried offline in the {@code --bundle} format, so this
 * needs no live Rekor call). Signing always happens elsewhere, in the tool/skill publisher's own
 * CI — AgentShield only ever verifies (§2, §11 of the design: no CA, no KMS, no private key
 * custody here).
 */
@Component
public class SigstoreSignatureVerifier implements SignatureVerifier {

    @Override
    public VerificationResult verify(byte[] artifactDigest, String bundleJson, String expectedIdentity,
            String expectedIssuer) {
        Bundle bundle;
        try {
            bundle = Bundle.from(new StringReader(bundleJson));
        } catch (Exception e) {
            return VerificationResult.failure("could not parse signature bundle: " + e.getMessage());
        }

        try {
            KeylessVerifier verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
            var optionsBuilder = VerificationOptions.builder();
            if (expectedIdentity != null && expectedIssuer != null) {
                optionsBuilder.addCertificateMatchers(VerificationOptions.CertificateMatcher.fulcio()
                        .subjectAlternativeName(StringMatcher.string(expectedIdentity))
                        .issuer(StringMatcher.string(expectedIssuer))
                        .build());
            }
            verifier.verify(artifactDigest, bundle, optionsBuilder.build());
            // The library already confirmed the certificate matches expectedIdentity/expectedIssuer
            // (when supplied) as part of verify() succeeding — nothing further to extract.
            return VerificationResult.success(expectedIdentity, expectedIssuer);
        } catch (KeylessVerificationException e) {
            return VerificationResult.failure("signature verification failed: " + e.getMessage());
        } catch (Exception e) {
            return VerificationResult.failure("signature verification error: " + e.getMessage());
        }
    }
}
