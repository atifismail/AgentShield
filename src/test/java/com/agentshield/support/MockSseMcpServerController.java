package com.agentshield.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * A minimal mock MCP server speaking the legacy MCP SSE transport (design-stdio-sse-mcp-
 * transport-and-sandboxing.md §9/§12): a persistent {@code GET} connection first emits an
 * {@code endpoint} event naming a session-scoped POST URL, then delivers JSON-RPC responses to
 * subsequent POSTs as {@code message} events on that same stream.
 */
@RestController
@RequestMapping("/demo/mock-sse-mcp-server")
public class MockSseMcpServerController {

    public static final AtomicBoolean dropConnectionOnConnect = new AtomicBoolean(false);
    public static final AtomicBoolean neverSendEndpointEvent = new AtomicBoolean(false);
    public static final AtomicBoolean sendOversizedResponse = new AtomicBoolean(false);
    public static final AtomicBoolean neverRespond = new AtomicBoolean(false);

    private static final Map<String, SseEmitter> sessions = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public static void reset() {
        dropConnectionOnConnect.set(false);
        neverSendEndpointEvent.set(false);
        sendOversizedResponse.set(false);
        neverRespond.set(false);
        sessions.clear();
    }

    @GetMapping
    public SseEmitter connect(HttpServletRequest request) {
        SseEmitter emitter = new SseEmitter(0L);
        if (dropConnectionOnConnect.get()) {
            emitter.complete();
            return emitter;
        }
        String sessionId = UUID.randomUUID().toString();
        sessions.put(sessionId, emitter);
        emitter.onCompletion(() -> sessions.remove(sessionId));
        emitter.onTimeout(() -> sessions.remove(sessionId));
        emitter.onError(e -> sessions.remove(sessionId));

        if (!neverSendEndpointEvent.get()) {
            try {
                String base = request.getRequestURL().toString();
                emitter.send(SseEmitter.event().name("endpoint").data(base + "/rpc?session=" + sessionId));
            } catch (IOException e) {
                emitter.completeWithError(e);
            }
        }
        return emitter;
    }

    @PostMapping("/rpc")
    public void rpc(@RequestParam("session") String sessionId, @RequestBody JsonNode request) throws IOException {
        SseEmitter emitter = sessions.get(sessionId);
        if (emitter == null) {
            return;
        }
        if (neverRespond.get()) {
            return;
        }

        String method = request.path("method").asText("");
        String id = request.path("id").asText("1");

        if (sendOversizedResponse.get()) {
            StringBuilder huge = new StringBuilder();
            huge.append("{\"jsonrpc\":\"2.0\",\"id\":").append(id).append(",\"result\":{\"data\":\"");
            huge.append("A".repeat(10_000));
            huge.append("\"}}");
            emitter.send(SseEmitter.event().name("message").data(huge.toString()));
            return;
        }

        ObjectNode response = objectMapper.createObjectNode();
        response.put("jsonrpc", "2.0");
        response.put("id", request.path("id").asLong(1));
        if ("tools/list".equals(method)) {
            response.set("result", toolsListResult());
        } else if ("tools/call".equals(method)) {
            response.set("result", toolsCallResult(request.path("params")));
        } else {
            ObjectNode error = objectMapper.createObjectNode();
            error.put("code", -32601);
            error.put("message", "method not found: " + method);
            response.set("error", error);
        }
        emitter.send(SseEmitter.event().name("message").data(objectMapper.writeValueAsString(response)));
    }

    private ObjectNode toolsListResult() {
        ObjectNode result = objectMapper.createObjectNode();
        ArrayNode tools = result.putArray("tools");
        ObjectNode echoTool = objectMapper.createObjectNode();
        echoTool.put("name", "echo");
        echoTool.put("description", "Echoes its input");
        echoTool.set("inputSchema", objectMapper.createObjectNode());
        tools.add(echoTool);
        return result;
    }

    private ObjectNode toolsCallResult(JsonNode params) {
        ObjectNode result = objectMapper.createObjectNode();
        result.put("toolName", params.path("name").asText());
        result.set("echoedArguments", params.path("arguments"));
        return result;
    }
}
