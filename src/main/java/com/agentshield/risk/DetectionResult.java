package com.agentshield.risk;

import java.util.Comparator;
import java.util.List;

/** Result of scanning a piece of text (typically a tool response) for a detector's indicators. */
public record DetectionResult(boolean matched, List<DetectionMatch> matches) {

    public static final DetectionResult CLEAN = new DetectionResult(false, List.of());

    public List<String> matchedIndicators() {
        return matches.stream().map(DetectionMatch::indicator).toList();
    }

    /** The strongest confidence among all matches, or null if nothing matched. */
    public Confidence highestConfidence() {
        return matches.stream().map(DetectionMatch::confidence).max(Comparator.naturalOrder()).orElse(null);
    }
}
