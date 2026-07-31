package com.agentshield.grant;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 2, "Policy order" §3-4.
 * Controls whether {@code Agent.allowedToolGroups} (legacy) or {@code agent_tool_grants}
 * (explicit) governs tool-group-level access for a given agent/tool pair.
 */
public enum GrantTransitionMode {
    /** Today's behavior: only the legacy allowed-tool-group string is consulted. Grants are ignored. */
    GROUPS_ONLY,
    /** If any grant (of any status) exists for the agent/tool pair, grants alone decide; otherwise the legacy group check applies. */
    GRANTS_OR_GROUPS,
    /** Grants alone decide; the legacy group string is never consulted. */
    GRANTS_REQUIRED
}
