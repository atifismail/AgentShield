package com.agentshield.siem;

/** Which subsystem produces a cataloged {@link DetectionRule} — matches the {@code detection_rules.source}
 * column (V16 migration). Cataloging, not new detection logic: every code here already fires today. */
public enum DetectionRuleSource {
    POLICY_RULE,
    BEHAVIOR_BASELINE,
    DLP,
    MCP_OAUTH,
    CODE_TRUST
}
