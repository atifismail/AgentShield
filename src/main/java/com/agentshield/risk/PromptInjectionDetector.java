package com.agentshield.risk;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

/**
 * Deterministic, keyword-based scan for prompt-injection attempts hidden in tool responses.
 * Indicators from PROJECT_PLAN.md section 12, extended with confidence/category metadata
 * (improvement_plan.md #9). No paid classification API is used or required.
 */
@Component
public class PromptInjectionDetector {

    private record InjectionIndicator(String phrase, DetectorCategory category, Confidence confidence) {
    }

    private static final List<InjectionIndicator> INDICATORS = List.of(
            new InjectionIndicator("ignore previous instructions", DetectorCategory.PROMPT_OVERRIDE, Confidence.HIGH),
            new InjectionIndicator("disregard system message", DetectorCategory.PROMPT_OVERRIDE, Confidence.HIGH),
            new InjectionIndicator("developer message override", DetectorCategory.PROMPT_OVERRIDE, Confidence.HIGH),
            new InjectionIndicator("system prompt", DetectorCategory.PROMPT_OVERRIDE, Confidence.LOW),
            new InjectionIndicator("reveal your secret", DetectorCategory.HIDDEN_INSTRUCTION, Confidence.HIGH),
            new InjectionIndicator("send credentials", DetectorCategory.HIDDEN_INSTRUCTION, Confidence.HIGH),
            new InjectionIndicator("do not tell the user", DetectorCategory.HIDDEN_INSTRUCTION, Confidence.HIGH),
            new InjectionIndicator("exfiltrate", DetectorCategory.HIDDEN_INSTRUCTION, Confidence.MEDIUM),
            new InjectionIndicator("hidden instruction", DetectorCategory.HIDDEN_INSTRUCTION, Confidence.MEDIUM),
            new InjectionIndicator("call this tool instead", DetectorCategory.TOOL_REDIRECTION, Confidence.HIGH));

    public DetectionResult scan(String text) {
        if (text == null || text.isBlank()) {
            return DetectionResult.CLEAN;
        }
        String lower = text.toLowerCase(Locale.ROOT);
        List<DetectionMatch> matches = new ArrayList<>();
        for (InjectionIndicator indicator : INDICATORS) {
            int offset = lower.indexOf(indicator.phrase());
            if (offset >= 0) {
                matches.add(new DetectionMatch(indicator.phrase(), indicator.category(), indicator.confidence(),
                        offset, indicator.phrase().length(), lineOf(lower, offset)));
            }
        }
        return matches.isEmpty() ? DetectionResult.CLEAN : new DetectionResult(true, matches);
    }

    private static int lineOf(String text, int offset) {
        int line = 1;
        for (int i = 0; i < offset; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }
}
