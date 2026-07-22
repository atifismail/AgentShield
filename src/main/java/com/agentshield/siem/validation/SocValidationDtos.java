package com.agentshield.siem.validation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import java.time.Instant;
import java.util.List;

public final class SocValidationDtos {

    private SocValidationDtos() {
    }

    public record ImportedAlertRequest(String alertName, String ruleId, Instant timestamp, String sourceEvent) {
        ImportedAlert toImportedAlert() {
            return new ImportedAlert(alertName, ruleId, timestamp, sourceEvent);
        }
    }

    public record ImportAlertsRequest(@NotEmpty @Valid List<ImportedAlertRequest> alerts) {
    }

    public record ImportAlertsResponse(Long validationRunId, int matchedCount, int missedCount, int unexpectedCount,
            List<String> matchedScenarios, List<String> missedScenarios, List<String> unexpectedAlertNames) {
    }
}
