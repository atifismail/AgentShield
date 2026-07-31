package com.agentshield.tool;

/**
 * Whether a tool has independent per-field fingerprints or only the legacy combined hash
 * (approved_hash/current_hash). A tool registered or refreshed before this release's migration
 * has {@code LEGACY_UNAVAILABLE} — that must read as "not computed", never as "confirmed
 * identical to an approved baseline".
 */
public enum ToolFingerprintState {
    AVAILABLE,
    LEGACY_UNAVAILABLE
}
