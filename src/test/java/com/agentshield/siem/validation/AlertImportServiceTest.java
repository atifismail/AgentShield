package com.agentshield.siem.validation;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Plain unit test (no Spring context) proving matched/missed/unexpected classification is correct
 * against a fixed manifest and a fixture-shaped alert list.
 */
class AlertImportServiceTest {

    private final AlertImportService service = new AlertImportService();

    private ExpectedDetectionsManifest manifest() {
        return new ExpectedDetectionsManifest(Map.of(
                "scenario-1", List.of("Tool Schema Drift"),
                "scenario-3", List.of("Secret Exposure Blocked", "Secret Leak Alert"),
                "scenario-4", List.of("Prompt Injection Blocked")));
    }

    @Test
    void scenarioWithAMatchingImportedAlertNameIsMatched() {
        var alerts = List.of(new ImportedAlert("Tool Schema Drift", "rule-1", Instant.now(), "src-1"));

        var result = service.evaluate(manifest(), alerts);

        assertThat(result.matchedScenarios()).containsExactly("scenario-1");
        assertThat(result.missedScenarios()).containsExactlyInAnyOrder("scenario-3", "scenario-4");
        assertThat(result.unexpectedAlerts()).isEmpty();
    }

    @Test
    void scenarioMatchesIfAnyOfItsExpectedAlertNamesIsPresent() {
        var alerts = List.of(new ImportedAlert("Secret Leak Alert", "rule-3", Instant.now(), "src-3"));

        var result = service.evaluate(manifest(), alerts);

        assertThat(result.matchedScenarios()).containsExactly("scenario-3");
        assertThat(result.missedScenarios()).containsExactlyInAnyOrder("scenario-1", "scenario-4");
    }

    @Test
    void scenarioWithNoMatchingImportedAlertIsMissed() {
        var result = service.evaluate(manifest(), List.of());

        assertThat(result.matchedScenarios()).isEmpty();
        assertThat(result.missedScenarios()).containsExactlyInAnyOrder("scenario-1", "scenario-3", "scenario-4");
    }

    @Test
    void importedAlertNotTiedToAnyExpectedNameIsUnexpected() {
        var alerts = List.of(
                new ImportedAlert("Tool Schema Drift", "rule-1", Instant.now(), "src-1"),
                new ImportedAlert("Totally Unrelated Alert", "rule-99", Instant.now(), "src-99"));

        var result = service.evaluate(manifest(), alerts);

        assertThat(result.unexpectedAlerts()).extracting(ImportedAlert::alertName)
                .containsExactly("Totally Unrelated Alert");
    }

    @Test
    void importedAlertWithNullNameIsTreatedAsUnexpected() {
        var alerts = List.of(new ImportedAlert(null, "rule-1", Instant.now(), "src-1"));

        var result = service.evaluate(manifest(), alerts);

        assertThat(result.unexpectedAlerts()).hasSize(1);
    }
}
