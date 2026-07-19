package com.agentshield.tool;

/**
 * Abstraction over Sigstore/cosign-compatible signature verification
 * (design-tool-supply-chain-provenance.md §5) — kept separate from {@link SigstoreSignatureVerifier}
 * so {@link ToolProvenanceService}'s gating/revocation business logic can be tested with a fake
 * implementation, independent of real Sigstore infrastructure (Fulcio/Rekor network calls, a
 * genuinely valid OIDC-signed bundle) that isn't practical to exercise in an offline test suite.
 */
public interface SignatureVerifier {

    /**
     * @param artifactDigest the SHA-256 digest of the exact bytes the publisher signed
     * @param bundleJson     a {@code cosign sign-blob --bundle} JSON artifact
     * @param expectedIdentity Sigstore keyless: the OIDC identity (email / CI workflow ref) the
     *                          signing certificate must have been issued to
     * @param expectedIssuer   Sigstore keyless: the OIDC issuer that must have authenticated the signer
     */
    VerificationResult verify(byte[] artifactDigest, String bundleJson, String expectedIdentity, String expectedIssuer);

    record VerificationResult(boolean verified, String certificateIdentity, String certificateIssuer,
            String details) {

        public static VerificationResult success(String certificateIdentity, String certificateIssuer) {
            return new VerificationResult(true, certificateIdentity, certificateIssuer,
                    "signature verified against Sigstore public trust root");
        }

        public static VerificationResult failure(String details) {
            return new VerificationResult(false, null, null, details);
        }
    }
}
