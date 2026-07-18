package com.agentshield.risk;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

/**
 * Deterministic, keyword-based scan for prompt-injection attempts hidden in tool responses.
 * Indicators from PROJECT_PLAN.md section 12. No paid classification API is used or required.
 */
@Component
public class PromptInjectionDetector {

    private static final List<String> INDICATORS = List.of(
            "ignore previous instructions",
            "disregard system message",
            "reveal your secret",
            "send credentials",
            "exfiltrate",
            "call this tool instead",
            "hidden instruction",
            "developer message override",
            "system prompt",
            "do not tell the user"
    );

    public DetectionResult scan(String text) {
        if (text == null || text.isBlank()) {
            return DetectionResult.CLEAN;
        }
        String lower = text.toLowerCase(Locale.ROOT);
        List<String> matches = new ArrayList<>();
        for (String indicator : INDICATORS) {
            if (lower.contains(indicator)) {
                matches.add(indicator);
            }
        }
        return matches.isEmpty() ? DetectionResult.CLEAN : new DetectionResult(true, matches);
    }
}
