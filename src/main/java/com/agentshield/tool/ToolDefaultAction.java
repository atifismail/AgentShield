package com.agentshield.tool;

/**
 * Operator-declared default disposition for a tool. Advisory metadata only in this release — it
 * does not itself change a gateway policy decision; the fixed rules and the policy engine keep
 * governing ALLOW/DENY/APPROVAL_REQUIRED exactly as before.
 */
public enum ToolDefaultAction {
    REVIEW,
    ALLOW,
    DENY
}
