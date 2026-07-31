package com.agentshield.grant;

/** Outcome of evaluating an agent/tool pair's grants for one gateway request. */
public enum GrantDecision {
    /** Grants don't govern this decision — either GROUPS_ONLY mode, or GRANTS_OR_GROUPS with no grants for this pair yet. */
    NOT_APPLICABLE,
    /** An active grant matched every constraint it declared. */
    SATISFIED,
    /** Grants govern this decision, but none matched. */
    DENIED
}
