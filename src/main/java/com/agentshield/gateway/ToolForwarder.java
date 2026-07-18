package com.agentshield.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Forwards an ALLOWed call to the tool's registered HTTP endpoint. Tool endpoints are normally
 * absolute URLs, but the bundled demo tools (com.agentshield.demo) are registered with
 * relative paths like "/demo/tools/git" since they live in this same application — those are
 * resolved against this server's own actual bound port (captured at startup, not the
 * configured value, so it's correct even when a random port is used, e.g. in tests).
 */
@Component
public class ToolForwarder {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private volatile String selfBaseUrl = "http://localhost:8080";

    public ToolForwarder(ObjectMapper objectMapper) {
        this.restClient = RestClient.create();
        this.objectMapper = objectMapper;
    }

    @EventListener
    public void onWebServerInitialized(WebServerInitializedEvent event) {
        this.selfBaseUrl = "http://localhost:" + event.getWebServer().getPort();
    }

    public ToolCallResult call(String endpointUrl, JsonNode input) {
        try {
            String resolvedUrl = endpointUrl != null && endpointUrl.startsWith("/")
                    ? selfBaseUrl + endpointUrl
                    : endpointUrl;
            String rawBody = restClient.post()
                    .uri(resolvedUrl)
                    .body(input == null ? objectMapper.createObjectNode() : input)
                    .retrieve()
                    .body(String.class);
            JsonNode parsed = parseOrWrap(rawBody);
            return new ToolCallResult(true, rawBody, parsed, null);
        } catch (Exception e) {
            return new ToolCallResult(false, null, null, e.getMessage());
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

    public record ToolCallResult(boolean success, String rawBody, JsonNode parsedBody, String errorMessage) {
    }
}
