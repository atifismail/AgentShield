package com.agentshield.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mock Git tool for the demo attack lab (docs/demo-lab.md). Registered in the seed data as
 * {@code mock-git} at {@code /demo/tools/git}. Not a real Git integration — it simulates
 * plausible commit/push/branch responses so the gateway has something realistic to forward to.
 */
@RestController
@Profile("demo")
@RequestMapping("/demo/tools/git")
public class GitToolController {

    @PostMapping
    public JsonNode handle(@RequestBody(required = false) JsonNode body) {
        ObjectNode response = JsonNodeFactory.instance.objectNode();
        response.put("tool", "mock-git");
        response.put("commitSha", "a1b2c3d4e5f6");
        response.put("status", "ok");
        if (body != null) {
            response.set("echoedInput", body);
        }
        return response;
    }
}
