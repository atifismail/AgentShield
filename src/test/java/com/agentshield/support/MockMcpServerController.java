package com.agentshield.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A minimal mock MCP server (JSON-RPC 2.0 over HTTP: {@code tools/list}, {@code tools/call})
 * for exercising MCP discovery/invocation in tests. Mounted under {@code /demo/**} for the same
 * reason as {@link MockToolController} — it's reached by server-to-server calls with no browser
 * session, so it's outside the authenticated UI/API surface.
 *
 * Test-controllable via static flags: {@link #echoToolDescription} lets a test simulate drift by
 * changing the description between two discovery calls; {@link #includeSecondTool} lets a test
 * simulate a tool disappearing between discoveries.
 */
@RestController
@RequestMapping("/demo/mock-mcp-server")
public class MockMcpServerController {

    public static final AtomicReference<String> echoToolDescription = new AtomicReference<>("Echoes its input");
    public static final AtomicBoolean includeSecondTool = new AtomicBoolean(true);

    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostMapping
    public ObjectNode handle(@RequestBody JsonNode request) {
        String method = request.path("method").asText("");
        ObjectNode response = objectMapper.createObjectNode();
        response.put("jsonrpc", "2.0");
        response.put("id", request.path("id").asInt(1));

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
        return response;
    }

    private ObjectNode toolsListResult() {
        ObjectNode result = objectMapper.createObjectNode();
        ArrayNode tools = result.putArray("tools");

        ObjectNode echoTool = objectMapper.createObjectNode();
        echoTool.put("name", "echo");
        echoTool.put("description", echoToolDescription.get());
        ObjectNode schema = objectMapper.createObjectNode();
        schema.put("type", "object");
        echoTool.set("inputSchema", schema);
        tools.add(echoTool);

        if (includeSecondTool.get()) {
            ObjectNode secondTool = objectMapper.createObjectNode();
            secondTool.put("name", "second-tool");
            secondTool.put("description", "A second mock tool");
            secondTool.set("inputSchema", objectMapper.createObjectNode());
            tools.add(secondTool);
        }
        return result;
    }

    private ObjectNode toolsCallResult(JsonNode params) {
        ObjectNode result = objectMapper.createObjectNode();
        result.put("toolName", params.path("name").asText());
        result.set("echoedArguments", params.path("arguments"));
        return result;
    }
}
