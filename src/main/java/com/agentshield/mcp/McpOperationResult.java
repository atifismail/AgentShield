package com.agentshield.mcp;

/** Shared success/failure result for transport-management operations (start/stop), stdio and SSE alike. */
public record McpOperationResult(boolean success, String errorMessage) {

    static McpOperationResult ok() {
        return new McpOperationResult(true, null);
    }

    static McpOperationResult fail(String errorMessage) {
        return new McpOperationResult(false, errorMessage);
    }
}
