package com.agentshield.mcp;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * design-stdio-sse-mcp-transport-and-sandboxing.md. Every default here is deliberately the most
 * restrictive reasonable choice — stdio transport spawns local subprocesses, the riskiest
 * capability in this codebase, so nothing is enabled or allowed until an operator explicitly says
 * so (§3, §5.1).
 */
@ConfigurationProperties(prefix = "agentshield.stdio")
public class StdioMcpProperties {

    /** Off by default (§3) — registering/discovering a STDIO server is rejected while false. */
    private boolean enabled = false;

    /** Executable names (not paths) allowed to spawn. Empty by default: nothing is spawnable (§5.1). */
    private List<String> allowedCommands = List.of();

    /**
     * When false (default), a command ending in .cmd/.bat is rejected — Windows batch-file
     * invocation goes through cmd.exe's own command-line parsing, a narrower but real
     * metacharacter risk that plain argv-array execution of a native binary doesn't have (§11).
     * Intended only for local Windows development, never production.
     */
    private boolean allowWindowsBatchCommands = false;

    /** Root directory under which each server gets its own sandbox subdirectory (§5.3). */
    private String sandboxRoot = "mcp-sandboxes";

    /** A process with no activity for this long is stopped by the idle reaper (§4.5). */
    private long idleTimeoutMinutes = 15;

    /** No matching JSON-RPC response within this window fails the call closed (§4.5). */
    private long callTimeoutSeconds = 30;

    /** A single response exceeding this many bytes aborts the read and kills the process (§4.3). */
    private long maxOutputBytes = 1_048_576;

    /** Total live stdio processes across all servers (§4.2 step 3). */
    private int maxConcurrentProcesses = 10;

    /**
     * Required to be true for the "prod" profile to start at all if {@link #enabled} is true
     * (§6a) — confirms subprocess isolation (network egress, resource limits) is enforced
     * externally, since AgentShield cannot enforce either from inside the JVM.
     */
    private boolean externalSandboxAcknowledged = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getAllowedCommands() {
        return allowedCommands;
    }

    public void setAllowedCommands(List<String> allowedCommands) {
        this.allowedCommands = allowedCommands;
    }

    public boolean isAllowWindowsBatchCommands() {
        return allowWindowsBatchCommands;
    }

    public void setAllowWindowsBatchCommands(boolean allowWindowsBatchCommands) {
        this.allowWindowsBatchCommands = allowWindowsBatchCommands;
    }

    public String getSandboxRoot() {
        return sandboxRoot;
    }

    public void setSandboxRoot(String sandboxRoot) {
        this.sandboxRoot = sandboxRoot;
    }

    public long getIdleTimeoutMinutes() {
        return idleTimeoutMinutes;
    }

    public void setIdleTimeoutMinutes(long idleTimeoutMinutes) {
        this.idleTimeoutMinutes = idleTimeoutMinutes;
    }

    public long getCallTimeoutSeconds() {
        return callTimeoutSeconds;
    }

    public void setCallTimeoutSeconds(long callTimeoutSeconds) {
        this.callTimeoutSeconds = callTimeoutSeconds;
    }

    public long getMaxOutputBytes() {
        return maxOutputBytes;
    }

    public void setMaxOutputBytes(long maxOutputBytes) {
        this.maxOutputBytes = maxOutputBytes;
    }

    public int getMaxConcurrentProcesses() {
        return maxConcurrentProcesses;
    }

    public void setMaxConcurrentProcesses(int maxConcurrentProcesses) {
        this.maxConcurrentProcesses = maxConcurrentProcesses;
    }

    public boolean isExternalSandboxAcknowledged() {
        return externalSandboxAcknowledged;
    }

    public void setExternalSandboxAcknowledged(boolean externalSandboxAcknowledged) {
        this.externalSandboxAcknowledged = externalSandboxAcknowledged;
    }
}
