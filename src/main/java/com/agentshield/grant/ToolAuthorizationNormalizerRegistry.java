package com.agentshield.grant;

import com.agentshield.tool.Tool;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Resolves the (currently empty) set of {@link ToolAuthorizationNormalizer} beans to the first
 * one that supports a given tool. With zero normalizers registered, every call resolves to
 * {@link NormalizedAuthorizationFacts#EMPTY} — the safe, documented release-one default.
 */
@Component
public class ToolAuthorizationNormalizerRegistry {

    private final List<ToolAuthorizationNormalizer> normalizers;

    public ToolAuthorizationNormalizerRegistry(List<ToolAuthorizationNormalizer> normalizers) {
        this.normalizers = normalizers;
    }

    public NormalizedAuthorizationFacts normalize(Tool tool, JsonNode input) {
        for (ToolAuthorizationNormalizer normalizer : normalizers) {
            if (normalizer.supports(tool)) {
                return normalizer.extract(tool, input);
            }
        }
        return NormalizedAuthorizationFacts.EMPTY;
    }
}
