package com.agentshield.siem.validation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;

/**
 * Checks a generic, externally-imported alert export against an
 * {@link ExpectedDetectionsManifest} — the vendor-neutral piece of the SOC validation module: it
 * proves whether a downstream SIEM/alerting tool actually caught what AgentShield's own scenario
 * catalog says should be catchable, without AgentShield knowing anything about that tool's own
 * rule format.
 */
@Service
public class AlertImportService {

    public record AlertImportResult(List<String> matchedScenarios, List<String> missedScenarios,
            List<ImportedAlert> unexpectedAlerts) {
    }

    public AlertImportResult evaluate(ExpectedDetectionsManifest manifest, List<ImportedAlert> importedAlerts) {
        Set<String> importedAlertNames = new HashSet<>();
        for (ImportedAlert alert : importedAlerts) {
            if (alert.alertName() != null) {
                importedAlertNames.add(alert.alertName());
            }
        }

        List<String> matched = new ArrayList<>();
        List<String> missed = new ArrayList<>();
        for (var entry : manifest.expectedAlertNamesByScenario().entrySet()) {
            boolean anyExpectedNamePresent = entry.getValue().stream().anyMatch(importedAlertNames::contains);
            (anyExpectedNamePresent ? matched : missed).add(entry.getKey());
        }

        Set<String> allExpectedNames = new HashSet<>();
        manifest.expectedAlertNamesByScenario().values().forEach(allExpectedNames::addAll);
        List<ImportedAlert> unexpected = importedAlerts.stream()
                .filter(a -> a.alertName() == null || !allExpectedNames.contains(a.alertName()))
                .toList();

        return new AlertImportResult(matched, missed, unexpected);
    }
}
