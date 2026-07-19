package com.agentshield.mcp;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * design-stdio-sse-mcp-transport-and-sandboxing.md §9. SSE is HTTP-based — no subprocess,
 * filesystem, or environment concerns apply, so unlike stdio there's no feature flag or command
 * allowlist: it's governed by the same {@link com.agentshield.gateway.OutboundEndpointValidator}
 * SSRF policy every other outbound call already goes through.
 */
@ConfigurationProperties(prefix = "agentshield.mcp.sse")
public class McpSseProperties {

    /** No matching JSON-RPC response within this window fails the call closed. */
    private long callTimeoutSeconds = 30;

    /** A connection with no activity for this long is closed by the idle reaper. */
    private long idleTimeoutMinutes = 15;

    /** A single event's accumulated data exceeding this many bytes aborts it and the connection. */
    private long maxResponseBytes = 1_048_576;

    /** Bounded reconnect attempts (with backoff) within a single connect attempt before failing closed. */
    private int reconnectMaxAttempts = 3;

    /** Initial backoff before the first reconnect attempt; doubles on each subsequent attempt. */
    private long reconnectInitialBackoffMillis = 500;

    public long getCallTimeoutSeconds() {
        return callTimeoutSeconds;
    }

    public void setCallTimeoutSeconds(long callTimeoutSeconds) {
        this.callTimeoutSeconds = callTimeoutSeconds;
    }

    public long getIdleTimeoutMinutes() {
        return idleTimeoutMinutes;
    }

    public void setIdleTimeoutMinutes(long idleTimeoutMinutes) {
        this.idleTimeoutMinutes = idleTimeoutMinutes;
    }

    public long getMaxResponseBytes() {
        return maxResponseBytes;
    }

    public void setMaxResponseBytes(long maxResponseBytes) {
        this.maxResponseBytes = maxResponseBytes;
    }

    public int getReconnectMaxAttempts() {
        return reconnectMaxAttempts;
    }

    public void setReconnectMaxAttempts(int reconnectMaxAttempts) {
        this.reconnectMaxAttempts = reconnectMaxAttempts;
    }

    public long getReconnectInitialBackoffMillis() {
        return reconnectInitialBackoffMillis;
    }

    public void setReconnectInitialBackoffMillis(long reconnectInitialBackoffMillis) {
        this.reconnectInitialBackoffMillis = reconnectInitialBackoffMillis;
    }
}
