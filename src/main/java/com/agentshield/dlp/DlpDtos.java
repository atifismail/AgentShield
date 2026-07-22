package com.agentshield.dlp;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public final class DlpDtos {

    private DlpDtos() {
    }

    public record RagScanRequest(@NotBlank String text, String sourceName) {
    }

    public record FindingSummary(String indicator, String category, String confidence) {
        static FindingSummary from(com.agentshield.risk.DetectionMatch match) {
            return new FindingSummary(match.indicator(), match.category().name(), match.confidence().name());
        }
    }

    public record RagScanResponse(DlpAction action, boolean blocked, String redactedText,
            java.util.List<FindingSummary> findings) {
        static RagScanResponse from(DlpScanResult result) {
            boolean blocked = result.action() == DlpAction.BLOCK;
            String redacted = (result.action() == DlpAction.REDACT || result.action() == DlpAction.TOKENIZE)
                    ? result.outputText()
                    : null;
            return new RagScanResponse(result.action(), blocked, redacted,
                    result.matches().stream().map(FindingSummary::from).toList());
        }
    }

    public record CreateProfileRequest(
            @NotBlank String name,
            String locale,
            Boolean detectSecrets,
            Boolean detectPii,
            Boolean detectPromptInjection,
            java.util.List<String> customPatterns,
            @NotNull DlpAction defaultAction,
            Integer priority
    ) {
    }

    public record ProfileResponse(
            Long id,
            String name,
            String locale,
            boolean enabled,
            boolean detectSecrets,
            boolean detectPii,
            boolean detectPromptInjection,
            DlpAction defaultAction,
            int priority,
            String createdBy,
            Instant createdAt
    ) {
        static ProfileResponse from(ClassificationProfile p) {
            return new ProfileResponse(p.getId(), p.getName(), p.getLocale(), p.isEnabled(), p.isDetectSecrets(),
                    p.isDetectPii(), p.isDetectPromptInjection(), p.getDefaultAction(), p.getPriority(),
                    p.getCreatedBy(), p.getCreatedAt());
        }
    }
}
