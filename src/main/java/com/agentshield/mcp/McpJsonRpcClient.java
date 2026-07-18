package com.agentshield.mcp;

import com.agentshield.gateway.OutboundEndpointValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.http.HttpClient;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Minimal JSON-RPC 2.0 over HTTP client for the MCP methods AgentShield needs
 * ({@code tools/list}, {@code tools/call}) — only the {@link McpTransportType#HTTP} transport is
 * implemented. Shares the same SSRF protection and no-redirect-follow policy as
 * {@link com.agentshield.gateway.ToolForwarder}, since this is the same class of outbound call.
 */
@Component
public class McpJsonRpcClient {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private final OutboundEndpointValidator outboundEndpointValidator;

    public McpJsonRpcClient(ObjectMapper objectMapper, OutboundEndpointValidator outboundEndpointValidator) {
        HttpClient jdkClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        this.restClient = RestClient.builder().requestFactory(new JdkClientHttpRequestFactory(jdkClient)).build();
        this.objectMapper = objectMapper;
        this.outboundEndpointValidator = outboundEndpointValidator;
    }

    public McpRpcResult call(String endpointUrl, String method, JsonNode params) {
        var validation = outboundEndpointValidator.validate(endpointUrl);
        if (!validation.allowed()) {
            return McpRpcResult.error("blocked by outbound endpoint policy: " + validation.reason());
        }
        try {
            ObjectNode request = objectMapper.createObjectNode();
            request.put("jsonrpc", "2.0");
            request.put("id", 1);
            request.put("method", method);
            request.set("params", params == null ? objectMapper.createObjectNode() : params);

            var responseEntity = restClient.post().uri(endpointUrl).body(request).retrieve().toEntity(String.class);
            if (responseEntity.getStatusCode().is3xxRedirection()) {
                return McpRpcResult.error("MCP server returned a redirect; redirects are never followed");
            }
            JsonNode responseJson = objectMapper.readTree(responseEntity.getBody());
            if (responseJson.has("error")) {
                return McpRpcResult.error("MCP server returned an error: " + responseJson.get("error"));
            }
            if (!responseJson.has("result")) {
                // Neither "result" nor "error" — this isn't a JSON-RPC response at all (e.g. the
                // endpoint isn't actually an MCP server). Treating a missing "result" as an empty
                // one would silently report "0 tools found" instead of surfacing the real problem.
                return McpRpcResult.error("response is not a valid JSON-RPC response (no \"result\" or \"error\" field)");
            }
            return McpRpcResult.success(responseJson.get("result"));
        } catch (Exception e) {
            return McpRpcResult.error("MCP call failed: " + e.getMessage());
        }
    }

    public record McpRpcResult(boolean success, JsonNode result, String errorMessage) {

        static McpRpcResult success(JsonNode result) {
            return new McpRpcResult(true, result, null);
        }

        static McpRpcResult error(String message) {
            return new McpRpcResult(false, null, message);
        }
    }
}
