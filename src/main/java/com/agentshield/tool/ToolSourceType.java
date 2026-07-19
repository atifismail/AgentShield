package com.agentshield.tool;

/** Where a tool came from — the trust boundary provenance verification is scoped by (design-tool-supply-chain-provenance.md §4). */
public enum ToolSourceType {
    /** The bundled demo tools (com.agentshield.demo) — always trusted, never requires verification. */
    BUILT_IN,
    /** Discovered via com.agentshield.mcp. */
    MCP,
    /** A locally-defined skill/prompt bundle (no entity yet — future). */
    LOCAL_SKILL,
    /** A downloaded package/command (future — stdio execution). */
    REMOTE_PACKAGE,
    /** A plain registered HTTP tool (ToolController.register). */
    CUSTOM_HTTP
}
