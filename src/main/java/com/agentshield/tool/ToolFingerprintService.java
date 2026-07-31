package com.agentshield.tool;

import com.agentshield.common.TokenHasher;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.stereotype.Component;

/**
 * Independent, canonicalized fingerprints for a tool's description/input-schema/output-schema
 * (agentshield_policy_evidence_execution_plan_2026-07-30.md work package 1). Object keys are
 * sorted recursively before hashing so JSON property reordering never looks like drift; array
 * order is preserved since it can be semantically significant. This is deliberately separate
 * from {@code Tool.currentHash}/{@code approvedHash} — the legacy combined fingerprint keeps its
 * original, un-canonicalized algorithm untouched so existing approved baselines never appear to
 * drift purely because this service was introduced.
 */
@Component
public class ToolFingerprintService {

    private final ObjectMapper objectMapper;

    public ToolFingerprintService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /** {@code null} means "no description supplied" and must be persisted as a null hash, not a hash of "". */
    public String hashDescription(String description) {
        if (description == null) {
            return null;
        }
        return TokenHasher.sha256Hex(normalizeWhitespace(description));
    }

    /**
     * {@code null}/blank means "no schema supplied". Invalid JSON is hashed as normalized raw
     * text rather than rejected — this service only fingerprints, it never validates schemas.
     */
    public String hashJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(json);
            String canonical = objectMapper.writeValueAsString(canonicalize(node));
            return TokenHasher.sha256Hex(canonical);
        } catch (Exception e) {
            return TokenHasher.sha256Hex(normalizeWhitespace(json));
        }
    }

    private String normalizeWhitespace(String text) {
        return text.trim().replaceAll("\\s+", " ");
    }

    private Object canonicalize(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        if (node.isObject()) {
            Map<String, Object> sorted = new TreeMap<>();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                sorted.put(entry.getKey(), canonicalize(entry.getValue()));
            }
            return sorted;
        }
        if (node.isArray()) {
            List<Object> elements = new ArrayList<>();
            for (JsonNode element : node) {
                elements.add(canonicalize(element));
            }
            return elements;
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isNumber()) {
            return node.decimalValue();
        }
        return node.asText();
    }
}
