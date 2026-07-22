package com.agentshield.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.support.AbstractIntegrationTest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Replays every demo-lab scenario in-process and asserts the expected {@link DetectionRule} fired
 * for each — a CI regression guard: if a control breaks, one of these assertions fails, matching
 * improvement_plan.md A5's "attack simulator proves rules fire" acceptance criterion.
 *
 * <p>Covers 12 of the SOC Validation Module's (N1) 13 scenarios — scenario-10 (MCP token misuse)
 * is a separate test, {@link McpTokenMisuseAttackScenarioTest}, since it genuinely needs the
 * test-only mock OAuth server; see {@link AttackSimulatorService}'s class javadoc for why.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AttackSimulatorIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private AttackSimulatorService attackSimulatorService;

    @Autowired
    private DetectionValidationRunRepository validationRunRepository;

    @Test
    void allTwelveInProcessScenariosProduceTheirExpectedDetection() {
        List<AttackSimulatorService.ScenarioResult> results = attackSimulatorService.runAll();

        assertThat(results).hasSize(12);
        Map<String, AttackSimulatorService.ScenarioResult> byCode = results.stream()
                .collect(java.util.stream.Collectors.toMap(AttackSimulatorService.ScenarioResult::scenarioCode, r -> r));

        results.forEach(r -> assertThat(r.passed())
                .as("scenario %s (%s): %s", r.scenarioCode(), r.description(), r.detail())
                .isTrue());

        assertThat(byCode.get("scenario-1").expectedDetectionRuleCode()).isEqualTo("deny-schema-drift");
        assertThat(byCode.get("scenario-2").expectedDetectionRuleCode()).isEqualTo("deny-prod-destructive-without-approval");
        assertThat(byCode.get("scenario-3").expectedDetectionRuleCode()).isEqualTo("deny-secret-external-transfer");
        assertThat(byCode.get("scenario-4").expectedDetectionRuleCode()).isEqualTo("deny-prompt-injection-response");
        assertThat(byCode.get("scenario-5").expectedDetectionRuleCode()).isEqualTo("require-approval-external-transfer");
        assertThat(byCode.get("scenario-6").expectedDetectionRuleCode()).isEqualTo("deny-tool-outside-allowed-group");
        assertThat(byCode.get("scenario-7").expectedDetectionRuleCode()).isEqualTo("deny-disabled-agent");
        assertThat(byCode.get("scenario-11").expectedDetectionRuleCode()).isEqualTo("deny-dlp-block");
        assertThat(byCode.get("scenario-12").expectedDetectionRuleCode()).isEqualTo("codetrust-blocked");
    }

    @Test
    void eachRunPersistsADetectionValidationRunRow() {
        long before = validationRunRepository.count();
        attackSimulatorService.runAll();
        long after = validationRunRepository.count();
        assertThat(after).isEqualTo(before + 12);
    }
}
