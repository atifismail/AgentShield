package com.agentshield.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

/**
 * Calls {@code tools/call} on the MCP server backing a given tool, normalizing the result.
 * Consent (is this agent allowed to use this MCP server at all?) is checked earlier, by
 * {@code PolicyEngine}'s pre-call evaluation (design-mcp-authorization.md §5/§8) — by the time
 * this class runs, the call has already been authorized. This class's own job is purely
 * mechanical: attach a valid OAuth token when the server requires one (§6).
 */
@Component
public class McpToolInvoker {

    private final McpServerRepository serverRepository;
    private final McpJsonRpcClient rpcClient;
    private final McpOAuthTokenService oauthTokenService;
    private final StdioMcpProcessManager stdioProcessManager;
    private final McpSseConnectionManager sseConnectionManager;
    private final ObjectMapper objectMapper;

    public McpToolInvoker(McpServerRepository serverRepository, McpJsonRpcClient rpcClient,
            McpOAuthTokenService oauthTokenService, StdioMcpProcessManager stdioProcessManager,
            McpSseConnectionManager sseConnectionManager, ObjectMapper objectMapper) {
        this.serverRepository = serverRepository;
        this.rpcClient = rpcClient;
        this.oauthTokenService = oauthTokenService;
        this.stdioProcessManager = stdioProcessManager;
        this.sseConnectionManager = sseConnectionManager;
        this.objectMapper = objectMapper;
    }

    public McpInvocationResult invoke(Long mcpServerId, String mcpToolName, JsonNode input) {
        var server = serverRepository.findById(mcpServerId).orElse(null);
        if (server == null) {
            return McpInvocationResult.failure("MCP server " + mcpServerId + " is no longer registered");
        }

        if (server.getTransportType() == McpTransportType.STDIO) {
            ObjectNode stdioParams = objectMapper.createObjectNode();
            stdioParams.put("name", mcpToolName);
            stdioParams.set("arguments", input == null ? objectMapper.createObjectNode() : input);
            var stdioResult = stdioProcessManager.call(server, "tools/call", stdioParams);
            if (!stdioResult.success()) {
                return McpInvocationResult.failure(stdioResult.errorMessage());
            }
            String stdioRawBody = stdioResult.result() == null ? "{}" : stdioResult.result().toString();
            return McpInvocationResult.success(stdioRawBody, stdioResult.result());
        }

        if (server.getTransportType() == McpTransportType.SSE) {
            ObjectNode sseParams = objectMapper.createObjectNode();
            sseParams.put("name", mcpToolName);
            sseParams.set("arguments", input == null ? objectMapper.createObjectNode() : input);
            var sseResult = sseConnectionManager.call(server, "tools/call", sseParams);
            if (!sseResult.success()) {
                return McpInvocationResult.failure(sseResult.errorMessage());
            }
            String sseRawBody = sseResult.result() == null ? "{}" : sseResult.result().toString();
            return McpInvocationResult.success(sseRawBody, sseResult.result());
        }

        String bearerToken = null;
        if (server.getAuthMode() == McpAuthMode.OAUTH2) {
            var tokenResult = oauthTokenService.getValidToken(server);
            if (!tokenResult.success()) {
                return McpInvocationResult.failure("could not obtain an OAuth token for MCP server '"
                        + server.getName() + "': " + tokenResult.errorMessage());
            }
            bearerToken = tokenResult.accessToken();
        }

        ObjectNode params = objectMapper.createObjectNode();
        params.put("name", mcpToolName);
        params.set("arguments", input == null ? objectMapper.createObjectNode() : input);

        var rpcResult = rpcClient.call(server.getEndpointUrl(), "tools/call", params, bearerToken);
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
