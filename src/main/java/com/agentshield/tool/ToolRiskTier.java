package com.agentshield.tool;

/** Operator-assigned risk classification for a tool, independent of live policy evaluation. */
public enum ToolRiskTier {
    UNCLASSIFIED,
    LOW,
    MODERATE,
    HIGH,
    CRITICAL
}
