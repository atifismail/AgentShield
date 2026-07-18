package com.agentshield.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mock SaaS CRM tool for the demo attack lab. Registered in the seed data as {@code mock-saas-crm}
 * at {@code /demo/tools/saas}. {@code exportRecords} is an EXTERNAL_TRANSFER action, so calling it
 * always requires human approval (policy rule 6) before this endpoint is ever reached
 * (docs/demo-lab.md scenario 5).
 */
@RestController
@RequestMapping("/demo/tools/saas")
public class SaasToolController {

    @PostMapping
    public JsonNode handle(@RequestBody(required = false) JsonNode body) {
        ObjectNode response = JsonNodeFactory.instance.objectNode();
        response.put("tool", "mock-saas-crm");
        response.put("recordsExported", 42);
        response.put("status", "ok");
        if (body != null) {
            response.set("echoedInput", body);
        }
        return response;
    }
}
