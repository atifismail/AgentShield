package com.agentshield.dlp;

/** What a {@link ClassificationProfile} does with content a detector matched. */
public enum DlpAction {
    ALLOW,
    REDACT,
    TOKENIZE,
    BLOCK,
    APPROVAL_REQUIRED
}
