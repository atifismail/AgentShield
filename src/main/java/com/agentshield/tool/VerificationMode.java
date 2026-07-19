package com.agentshield.tool;

public enum VerificationMode {
    /** No signature checked, checksum-only. Default; matches pre-provenance behavior exactly. */
    UNVERIFIED,
    /** Checksum recorded and matches on every refresh; still Level 1 (no cryptographic signature). */
    CHECKSUM_PINNED,
    /** A Sigstore bundle was checked and passed. Level 2. */
    SIGNATURE_VERIFIED,
    /** A signature was present but failed verification — claims an identity that doesn't check out. */
    SIGNATURE_FAILED,
    /** A previously-verified provenance record whose signing identity/key was later revoked. */
    REVOKED
}
