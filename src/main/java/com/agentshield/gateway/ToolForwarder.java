package com.agentshield.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Forwards an ALLOWed call to the tool's registered HTTP endpoint. Tool endpoints are normally
 * absolute URLs, but the bundled demo tools (com.agentshield.demo) are registered with
 * relative paths like "/demo/tools/git" since they live in this same application — those are
 * resolved against this server's own actual bound port (captured at startup, not the
 * configured value, so it's correct even when a random port is used, e.g. in tests).
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
    private volatile String selfBaseUrl = "http://localhost:8080";

    public ToolForwarder(ObjectMapper objectMapper, OutboundEndpointValidator outboundEndpointValidator) {
        HttpClient jdkClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.restClient = RestClient.builder()
                .requestFactory(new JdkClientHttpRequestFactory(jdkClient))
                .build();
        this.objectMapper = objectMapper;
        this.outboundEndpointValidator = outboundEndpointValidator;
    }

    @EventListener
    public void onWebServerInitialized(WebServerInitializedEvent event) {
        this.selfBaseUrl = "http://localhost:" + event.getWebServer().getPort();
    }

    public ToolCallResult call(String endpointUrl, JsonNode input) {
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
