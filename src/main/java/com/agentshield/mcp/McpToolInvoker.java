package com.agentshield.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

/** Calls {@code tools/call} on the MCP server backing a given tool, normalizing the result. */
@Component
public class McpToolInvoker {

    private final McpServerRepository serverRepository;
    private final McpJsonRpcClient rpcClient;
    private final ObjectMapper objectMapper;

    public McpToolInvoker(McpServerRepository serverRepository, McpJsonRpcClient rpcClient, ObjectMapper objectMapper) {
        this.serverRepository = serverRepository;
        this.rpcClient = rpcClient;
        this.objectMapper = objectMapper;
    }

    public McpInvocationResult invoke(Long mcpServerId, String mcpToolName, JsonNode input) {
        var server = serverRepository.findById(mcpServerId).orElse(null);
        if (server == null) {
            return McpInvocationResult.failure("MCP server " + mcpServerId + " is no longer registered");
        }
        if (server.getTransportType() != McpTransportType.HTTP) {
            return McpInvocationResult.failure(
                    "invocation for transport " + server.getTransportType() + " is not implemented yet");
        }

        ObjectNode params = objectMapper.createObjectNode();
        params.put("name", mcpToolName);
        params.set("arguments", input == null ? objectMapper.createObjectNode() : input);

        var rpcResult = rpcClient.call(server.getEndpointUrl(), "tools/call", params);
        if (!rpcResult.success()) {
            return McpInvocationResult.failure(rpcResult.errorMessage());
        }
        String rawBody = rpcResult.result() == null ? "{}" : rpcResult.result().toString();
        return McpInvocationResult.success(rawBody, rpcResult.result());
    }

    public record McpInvocationResult(boolean success, String rawBody, JsonNode parsedBody, String errorMessage) {

        static McpInvocationResult success(String rawBody, JsonNode parsedBody) {
            return new McpInvocationResult(true, rawBody, parsedBody, null);
        }

        static McpInvocationResult failure(String errorMessage) {
            return new McpInvocationResult(false, null, null, errorMessage);
        }
    }
}
