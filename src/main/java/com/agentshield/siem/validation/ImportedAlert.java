package com.agentshield.siem.validation;

import java.time.Instant;

/**
 * One row from a generic, externally-exported alert list — deliberately vendor-neutral (no
 * Elastic/Splunk/Logpresso-specific field names) per the trimmed-MVP scope decision. An operator
 * exports whatever their SIEM/alerting tool produced and maps it into this shape before import.
 */
public record ImportedAlert(String alertName, String ruleId, Instant timestamp, String sourceEvent) {
}
