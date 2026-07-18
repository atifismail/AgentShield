package com.agentshield.risk;

import java.util.List;

/** Result of scanning a piece of text (typically a tool response) for a detector's indicators. */
public record DetectionResult(boolean matched, List<String> matchedIndicators) {

    public static final DetectionResult CLEAN = new DetectionResult(false, List.of());
}
