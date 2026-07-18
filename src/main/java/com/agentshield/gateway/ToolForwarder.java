package com.agentshield.gateway;

import com.agentshield.mcp.McpToolInvoker;
import com.agentshield.tool.Tool;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Forwards an ALLOWed call to its tool. Plain tools go straight to their registered HTTP
 * endpoint; MCP-backed tools ({@link Tool#isMcpBacked()}) are delegated to
 * {@link McpToolInvoker} instead, which speaks MCP's JSON-RPC {@code tools/call} to the owning
 * MCP server. Either way the caller (GatewayService) sees the same {@link ToolCallResult} shape.
 *
 * Tool endpoints are normally absolute URLs, but the bundled demo tools (com.agentshield.demo)
 * are registered with relative paths like "/demo/tools/git" since they live in this same
 * application — those are resolved against this server's own actual bound port (captured at
 * startup, not the configured value, so it's correct even when a random port is used, e.g. in
 * tests).
 *
 * Re-validates the outbound endpoint immediately before every call (registration-time
 * validation alone isn't enough — DNS can change between registration and call, a classic
 * SSRF TOCTOU gap) and never follows HTTP redirects, since a redirect is a common way to route
 * around a host-based allowlist check.
 */
@Component
public class ToolForwarder {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private final OutboundEndpointValidator outboundEndpointValidator;
    private final McpToolInvoker mcpToolInvoker;
    private volatile String selfBaseUrl = "http://localhost:8080";

    public ToolForwarder(ObjectMapper objectMapper, OutboundEndpointValidator outboundEndpointValidator,
            McpToolInvoker mcpToolInvoker) {
        HttpClient jdkClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.restClient = RestClient.builder()
                .requestFactory(new JdkClientHttpRequestFactory(jdkClient))
                .build();
        this.objectMapper = objectMapper;
        this.outboundEndpointValidator = outboundEndpointValidator;
        this.mcpToolInvoker = mcpToolInvoker;
    }

    @EventListener
    public void onWebServerInitialized(WebServerInitializedEvent event) {
        this.selfBaseUrl = "http://localhost:" + event.getWebServer().getPort();
    }

    public ToolCallResult call(Tool tool, JsonNode input) {
        if (tool.isMcpBacked()) {
            var result = mcpToolInvoker.invoke(tool.getMcpServerId(), tool.getMcpToolName(), input);
            return result.success()
                    ? new ToolCallResult(true, false, result.rawBody(), result.parsedBody(), null)
                    : new ToolCallResult(false, false, null, null, result.errorMessage());
        }
        return callHttp(tool.getEndpointUrl(), input);
    }

    private ToolCallResult callHttp(String endpointUrl, JsonNode input) {
        var validation = outboundEndpointValidator.validate(endpointUrl);
        if (!validation.allowed()) {
            return ToolCallResult.blocked("blocked by outbound endpoint policy: " + validation.reason());
        }

        try {
            String resolvedUrl = endpointUrl != null && endpointUrl.startsWith("/")
                    ? selfBaseUrl + endpointUrl
                    : endpointUrl;
            var responseEntity = restClient.post()
                    .uri(resolvedUrl)
                    .body(input == null ? objectMapper.createObjectNode() : input)
                    .retrieve()
                    .toEntity(String.class);

            if (responseEntity.getStatusCode().is3xxRedirection()) {
                return ToolCallResult.blocked(
                        "tool endpoint returned a redirect (" + responseEntity.getStatusCode()
                                + "); redirects are never followed");
            }

            String rawBody = responseEntity.getBody();
            JsonNode parsed = parseOrWrap(rawBody);
            return new ToolCallResult(true, false, rawBody, parsed, null);
        } catch (Exception e) {
            return new ToolCallResult(false, false, null, null, e.getMessage());
        }
    }

    private JsonNode parseOrWrap(String rawBody) {
        if (rawBody == null || rawBody.isBlank()) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(rawBody);
        } catch (Exception e) {
            return objectMapper.createObjectNode().put("raw", rawBody);
        }
    }

    public record ToolCallResult(boolean success, boolean blockedByPolicy, String rawBody, JsonNode parsedBody,
            String errorMessage) {

        static ToolCallResult blocked(String reason) {
            return new ToolCallResult(false, true, null, null, reason);
        }
    }
}
