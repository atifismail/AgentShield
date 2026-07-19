package com.agentshield.mcp;

import com.agentshield.common.AuditSeverity;
import com.agentshield.gateway.OutboundEndpointValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.annotation.PreDestroy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.http.HttpHeaders;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Owns every live SSE connection to an MCP server (design-stdio-sse-mcp-transport-and-sandboxing.md
 * §9) — much smaller in scope than {@link StdioMcpProcessManager} since SSE is plain HTTP: no
 * subprocess, filesystem, or environment-variable concerns, and network egress is already governed
 * by {@link OutboundEndpointValidator} the same as any other outbound call. Per the (legacy) MCP
 * SSE transport spec: a persistent {@code GET} connection first receives an {@code endpoint} event
 * naming a session-scoped POST URL; {@code tools/list}/{@code tools/call} requests are POSTed
 * there, and responses arrive asynchronously as {@code message} events on the original stream,
 * correlated by JSON-RPC {@code id}. Unlike stdio, concurrent in-flight requests over one
 * connection are the natural model here (no shared stdin/stdout ordering to protect), so calls are
 * not serialized.
 */
@Component
public class McpSseConnectionManager {

    private final McpSseProperties properties;
    private final OutboundEndpointValidator outboundEndpointValidator;
    private final McpOAuthTokenService oauthTokenService;
    private final McpSseAuditRecorder auditRecorder;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final RestClient restClient;
    private final Map<Long, ManagedSseConnection> connections = new ConcurrentHashMap<>();
    private final AtomicLong requestIdSeq = new AtomicLong(1);
    private final java.util.concurrent.ExecutorService readerExecutor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "mcp-sse-reader");
        t.setDaemon(true);
        return t;
    });

    public McpSseConnectionManager(McpSseProperties properties, OutboundEndpointValidator outboundEndpointValidator,
            McpOAuthTokenService oauthTokenService, McpSseAuditRecorder auditRecorder, ObjectMapper objectMapper) {
        this.properties = properties;
        this.outboundEndpointValidator = outboundEndpointValidator;
        this.oauthTokenService = oauthTokenService;
        this.auditRecorder = auditRecorder;
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.restClient = RestClient.builder()
                .requestFactory(new org.springframework.http.client.JdkClientHttpRequestFactory(
                        HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()))
                .build();
    }

    public SseRpcResult call(McpServer server, String method, JsonNode params) {
        ManagedSseConnection conn;
        try {
            conn = getOrConnect(server);
        } catch (SseConnectFailedException e) {
            return SseRpcResult.error(e.getMessage());
        }

        long requestId = requestIdSeq.getAndIncrement();
        CompletableFuture<SseRpcResult> future = new CompletableFuture<>();
        conn.pendingRequests.put(requestId, future);

        try {
            ObjectNode request = objectMapper.createObjectNode();
            request.put("jsonrpc", "2.0");
            request.put("id", requestId);
            request.put("method", method);
            request.set("params", params == null ? objectMapper.createObjectNode() : params);

            String bearerToken = resolveBearerToken(server);
            restClient.post().uri(conn.postUrl)
                    .headers(headers -> {
                        if (bearerToken != null) {
                            headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
                        }
                    })
                    .body(request).retrieve().toBodilessEntity();
        } catch (Exception e) {
            conn.pendingRequests.remove(requestId);
            return SseRpcResult.error("failed to send SSE MCP request: " + e.getMessage());
        }

        try {
            SseRpcResult result = future.get(properties.getCallTimeoutSeconds(), TimeUnit.SECONDS);
            conn.lastActivityAt = Instant.now();
            return result;
        } catch (TimeoutException e) {
            conn.pendingRequests.remove(requestId);
            auditRecorder.record("mcp.sse_call_timeout", AuditSeverity.WARNING,
                    "SSE call to MCP server '" + server.getName() + "' timed out after "
                            + properties.getCallTimeoutSeconds() + "s", null);
            return SseRpcResult.error("SSE call to MCP server '" + server.getName() + "' timed out");
        } catch (ExecutionException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            conn.pendingRequests.remove(requestId);
            return SseRpcResult.error("SSE call failed: " + e.getMessage());
        }
    }

    public McpDtos.McpTransportStatusResponse status(Long serverId) {
        ManagedSseConnection conn = connections.get(serverId);
        if (conn == null || conn.closed.get()) {
            return new McpDtos.McpTransportStatusResponse(false, null, null, null);
        }
        return new McpDtos.McpTransportStatusResponse(true, null, conn.connectedAt, conn.lastActivityAt);
    }

    public void stop(McpServer server) {
        ManagedSseConnection conn = connections.remove(server.getId());
        if (conn != null) {
            closeConnection(conn, "manual");
        }
    }

    public McpOperationResult start(McpServer server) {
        try {
            getOrConnect(server);
            return McpOperationResult.ok();
        } catch (SseConnectFailedException e) {
            return McpOperationResult.fail(e.getMessage());
        }
    }

    @Scheduled(fixedDelayString = "PT1M")
    public void reapIdleConnections() {
        Instant cutoff = Instant.now().minus(Duration.ofMinutes(properties.getIdleTimeoutMinutes()));
        for (Map.Entry<Long, ManagedSseConnection> entry : connections.entrySet()) {
            ManagedSseConnection conn = entry.getValue();
            if (conn.lastActivityAt.isBefore(cutoff) && connections.remove(entry.getKey(), conn)) {
                closeConnection(conn, "idle");
            }
        }
    }

    @PreDestroy
    void shutdown() {
        connections.forEach((id, conn) -> closeConnection(conn, "shutdown"));
        readerExecutor.shutdownNow();
    }

    private String resolveBearerToken(McpServer server) {
        if (server.getAuthMode() != McpAuthMode.OAUTH2) {
            return null;
        }
        var tokenResult = oauthTokenService.getValidToken(server);
        return tokenResult.success() ? tokenResult.accessToken() : null;
    }

    private ManagedSseConnection getOrConnect(McpServer server) throws SseConnectFailedException {
        AtomicReference<SseConnectFailedException> failure = new AtomicReference<>();
        ManagedSseConnection result = connections.compute(server.getId(), (id, existing) -> {
            if (existing != null && !existing.closed.get()) {
                return existing;
            }
            try {
                return connectWithRetries(server);
            } catch (SseConnectFailedException e) {
                failure.set(e);
                return null;
            }
        });
        if (failure.get() != null) {
            throw failure.get();
        }
        return result;
    }

    private ManagedSseConnection connectWithRetries(McpServer server) throws SseConnectFailedException {
        long backoff = properties.getReconnectInitialBackoffMillis();
        Exception lastError = null;
        for (int attempt = 1; attempt <= Math.max(1, properties.getReconnectMaxAttempts()); attempt++) {
            try {
                return connectOnce(server);
            } catch (Exception e) {
                lastError = e;
                if (attempt < properties.getReconnectMaxAttempts()) {
                    try {
                        Thread.sleep(backoff);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    backoff *= 2;
                }
            }
        }
        String reason = "could not establish an SSE connection to MCP server '" + server.getName() + "': "
                + (lastError == null ? "unknown error" : lastError.getMessage());
        auditRecorder.record("mcp.sse_connection_failed", AuditSeverity.WARNING, reason, null);
        throw new SseConnectFailedException(reason);
    }

    private ManagedSseConnection connectOnce(McpServer server) throws Exception {
        var validation = outboundEndpointValidator.validate(server.getEndpointUrl());
        if (!validation.allowed()) {
            throw new IllegalStateException("blocked by outbound endpoint policy: " + validation.reason());
        }

        String bearerToken = resolveBearerToken(server);
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(URI.create(server.getEndpointUrl()))
                .GET()
                .header("Accept", "text/event-stream")
                .timeout(Duration.ofSeconds(properties.getCallTimeoutSeconds()));
        if (bearerToken != null) {
            requestBuilder.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }

        HttpResponse<java.util.stream.Stream<String>> response = httpClient.send(requestBuilder.build(),
                HttpResponse.BodyHandlers.ofLines());
        if (response.statusCode() / 100 == 3) {
            throw new IllegalStateException("MCP server returned a redirect; redirects are never followed");
        }
        if (response.statusCode() != 200) {
            throw new IllegalStateException("MCP server returned HTTP " + response.statusCode());
        }

        ManagedSseConnection conn = new ManagedSseConnection(server.getId(), server.getName(), Instant.now());
        java.util.concurrent.CountDownLatch endpointReady = new java.util.concurrent.CountDownLatch(1);
        readerExecutor.submit(() -> readEvents(server, conn, response.body().iterator(), endpointReady));

        boolean gotEndpoint = endpointReady.await(properties.getCallTimeoutSeconds(), TimeUnit.SECONDS);
        if (!gotEndpoint || conn.postUrl == null) {
            conn.closed.set(true);
            throw new IllegalStateException("MCP server never sent an \"endpoint\" event within the timeout");
        }

        auditRecorder.record("mcp.sse_connection_opened", AuditSeverity.INFO,
                "SSE connection opened to MCP server '" + server.getName() + "'", null);
        return conn;
    }

    /** Runs on a dedicated reader thread for the lifetime of one connection. */
    private void readEvents(McpServer server, ManagedSseConnection conn, Iterator<String> lines,
            java.util.concurrent.CountDownLatch endpointReady) {
        String eventType = "message";
        StringBuilder data = new StringBuilder();
        long dataBytes = 0;
        boolean oversized = false;
        try {
            while (!conn.closed.get() && lines.hasNext()) {
                String line = lines.next();
                if (line.isEmpty()) {
                    if (!oversized && data.length() > 0) {
                        handleEvent(server, conn, eventType, data.toString(), endpointReady);
                    }
                    eventType = "message";
                    data.setLength(0);
                    dataBytes = 0;
                    oversized = false;
                    continue;
                }
                if (line.startsWith("event:")) {
                    eventType = line.substring(6).trim();
                } else if (line.startsWith("data:")) {
                    String chunk = line.substring(5).trim();
                    dataBytes += chunk.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                    if (dataBytes > properties.getMaxResponseBytes()) {
                        oversized = true;
                        continue;
                    }
                    if (data.length() > 0) {
                        data.append('\n');
                    }
                    data.append(chunk);
                }
            }
            if (oversized) {
                auditRecorder.record("mcp.sse_response_rejected", AuditSeverity.WARNING,
                        "SSE response from MCP server '" + server.getName()
                                + "' exceeded agentshield.mcp.sse.max-response-bytes and was rejected", null);
            }
        } catch (Exception e) {
            // stream closed/errored — fall through to cleanup below
        } finally {
            conn.closed.set(true);
            connections.remove(server.getId(), conn);
            for (var pending : conn.pendingRequests.values()) {
                pending.completeExceptionally(new IllegalStateException("SSE connection to '" + server.getName() + "' closed"));
            }
            auditRecorder.record("mcp.sse_connection_closed", AuditSeverity.INFO,
                    "SSE connection to MCP server '" + server.getName() + "' closed", null);
        }
    }

    private void handleEvent(McpServer server, ManagedSseConnection conn, String eventType, String data,
            java.util.concurrent.CountDownLatch endpointReady) {
        if ("endpoint".equals(eventType)) {
            conn.postUrl = resolvePostUrl(server.getEndpointUrl(), data);
            endpointReady.countDown();
            return;
        }
        JsonNode json;
        try {
            json = objectMapper.readTree(data);
        } catch (Exception e) {
            return; // not a JSON-RPC message; ignore
        }
        if (!json.has("id")) {
            return;
        }
        long id = json.get("id").asLong(-1);
        var future = conn.pendingRequests.remove(id);
        if (future == null) {
            return;
        }
        if (json.has("error")) {
            future.complete(SseRpcResult.error("SSE MCP server returned an error: " + json.get("error")));
        } else if (json.has("result")) {
            future.complete(SseRpcResult.success(json.get("result")));
        } else {
            future.complete(SseRpcResult.error("response is not a valid JSON-RPC response (no \"result\" or \"error\" field)"));
        }
    }

    private String resolvePostUrl(String endpointUrl, String eventData) {
        try {
            return URI.create(endpointUrl).resolve(eventData.trim()).toString();
        } catch (Exception e) {
            return eventData.trim();
        }
    }

    private void closeConnection(ManagedSseConnection conn, String reason) {
        conn.closed.set(true);
        for (var pending : conn.pendingRequests.values()) {
            pending.completeExceptionally(new IllegalStateException("SSE connection closed (" + reason + ")"));
        }
        auditRecorder.record("mcp.sse_connection_closed", AuditSeverity.INFO,
                "SSE connection to MCP server '" + conn.serverName + "' closed (reason=" + reason + ")", null);
    }

    private static final class ManagedSseConnection {
        final Long serverId;
        final String serverName;
        final Instant connectedAt;
        volatile String postUrl;
        volatile Instant lastActivityAt;
        final AtomicBoolean closed = new AtomicBoolean(false);
        final Map<Long, CompletableFuture<SseRpcResult>> pendingRequests = new ConcurrentHashMap<>();

        ManagedSseConnection(Long serverId, String serverName, Instant connectedAt) {
            this.serverId = serverId;
            this.serverName = serverName;
            this.connectedAt = connectedAt;
            this.lastActivityAt = connectedAt;
        }
    }

    private static final class SseConnectFailedException extends Exception {
        SseConnectFailedException(String message) {
            super(message);
        }
    }

    public record SseRpcResult(boolean success, JsonNode result, String errorMessage) {
        static SseRpcResult success(JsonNode result) {
            return new SseRpcResult(true, result, null);
        }

        static SseRpcResult error(String message) {
            return new SseRpcResult(false, null, message);
        }
    }
}
