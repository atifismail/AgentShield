package com.agentshield.risk;

/**
 * A single detector hit. {@code offset}/{@code line} locate the match within the scanned text
 * (both -1 if not applicable) so an investigator can find it without the matched text itself
 * ever being stored — only the indicator name, category, and confidence leave the detector.
 * {@code length} is the span of the match in characters (0 if not applicable/unknown), needed by
 * {@link com.agentshield.dlp.RedactionService} to know exactly which characters to replace
 * without ever being handed the matched substring itself.
 */
public record DetectionMatch(String indicator, DetectorCategory category, Confidence confidence, int offset,
        int length, int line) {
}
