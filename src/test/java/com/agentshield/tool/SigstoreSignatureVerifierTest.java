package com.agentshield.tool;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * design-tool-supply-chain-provenance.md §13. Deliberately scoped to what's testable offline —
 * an unparseable bundle fails during {@code Bundle.from(...)}, before any Sigstore network call
 * is ever made, so this needs no network access and is fully deterministic. A genuinely valid
 * signature (or a well-formed-but-cryptographically-bogus one) would require live Sigstore
 * infrastructure (Fulcio/Rekor/TUF) and a real signed artifact to exercise — neither reproducible
 * in this offline suite. {@link ToolProvenanceServiceTest} covers the orchestration logic around
 * verification (gating, revocation, state transitions) with a mocked {@link SignatureVerifier}
 * instead.
 */
class SigstoreSignatureVerifierTest {

    private final SigstoreSignatureVerifier verifier = new SigstoreSignatureVerifier();

    @Test
    void rejectsAnUnparseableBundleWithoutMakingAnyNetworkCall() {
        var result = verifier.verify(new byte[32], "this is not valid sigstore bundle json",
                "me@example.com", "https://issuer.example.com");

        assertThat(result.verified()).isFalse();
        assertThat(result.details()).contains("could not parse signature bundle");
    }

    @Test
    void rejectsAnEmptyBundle() {
        var result = verifier.verify(new byte[32], "", "me@example.com", "https://issuer.example.com");

        assertThat(result.verified()).isFalse();
    }

    @Test
    void rejectsAWellFormedButIncompleteBundle() {
        // Valid JSON, but missing every field a real cosign sign-blob --bundle output would have.
        var result = verifier.verify(new byte[32], "{}", "me@example.com", "https://issuer.example.com");

        assertThat(result.verified()).isFalse();
    }
}
