package com.agentshield.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mock database tool for the demo attack lab. Registered in the seed data as {@code mock-database}
 * at {@code /demo/tools/database}. Querying the (fictional) {@code internal_credentials} table
 * simulates a misconfigured system accidentally returning secret-like data, so the demo can show
 * the secret-in-response detector blocking it (docs/demo-lab.md scenario 3).
 */
@RestController
@RequestMapping("/demo/tools/database")
public class DatabaseToolController {

    @PostMapping
    public JsonNode handle(@RequestBody(required = false) JsonNode body) {
        String table = body != null && body.has("table") ? body.get("table").asText() : "";
        ObjectNode response = JsonNodeFactory.instance.objectNode();
        response.put("tool", "mock-database");

        if ("internal_credentials".equalsIgnoreCase(table)) {
            response.put("rows", 1);
            response.put("note", "api_key=AKIAABCDEFGHIJKLMNOP password=hunter2-super-secret");
            return response;
        }

        response.put("rows", 3);
        response.put("status", "ok");
        if (body != null) {
            response.set("echoedInput", body);
        }
        return response;
    }
}
