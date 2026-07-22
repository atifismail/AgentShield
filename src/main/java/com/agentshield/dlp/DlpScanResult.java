package com.agentshield.dlp;

import com.agentshield.risk.DetectionMatch;
import java.util.List;

/**
 * @param action     what the resolved classification profile says to do about the strongest
 *                    finding in this scan (ALLOW if nothing matched).
 * @param outputText the text to actually use going forward — equal to the input unless
 *                    {@code action} is REDACT/TOKENIZE, in which case matched spans are replaced.
 * @param matches    every detector hit from this scan, across all three detectors.
 */
public record DlpScanResult(DlpAction action, String outputText, List<DetectionMatch> matches) {

    public boolean isAllow() {
        return action == DlpAction.ALLOW || action == DlpAction.REDACT || action == DlpAction.TOKENIZE;
    }
}
