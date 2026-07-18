package com.agentshield.risk;

/**
 * A single detector hit. {@code offset}/{@code line} locate the match within the scanned text
 * (both -1 if not applicable) so an investigator can find it without the matched text itself
 * ever being stored — only the indicator name, category, and confidence leave the detector.
 */
public record DetectionMatch(String indicator, DetectorCategory category, Confidence confidence, int offset,
        int line) {
}
