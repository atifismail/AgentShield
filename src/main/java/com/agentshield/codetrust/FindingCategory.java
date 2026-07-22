package com.agentshield.codetrust;

/** What kind of problem a {@link CodeFinding} represents. */
public enum FindingCategory {
    SECRET,
    LICENSE,
    DEPENDENCY_RISK,
    INSECURE_PATTERN,
    CRYPTO_AUTH_CHANGE
}
