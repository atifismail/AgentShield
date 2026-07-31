package com.agentshield.evaluation;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.PolicyDecisionType;
import com.agentshield.evaluation.EvaluationDtos.CaseImport;
import com.agentshield.evaluation.EvaluationDtos.CreateSuiteRequest;
import com.agentshield.support.AbstractIntegrationTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 4, "Editing an approved/
 * released suite creates a new version/checksum. Historical runs remain reproducible against
 * their stored suite version" and "Suites cannot be overwritten in place after a run."
 */
@SpringBootTest
class EvaluationSuiteVersioningTest extends AbstractIntegrationTest {

    @Autowired
    private EvaluationSuiteService suiteService;
    @Autowired
    private EvaluationSuiteRepository suiteRepository;
    @Autowired
    private EvaluationCaseRepository caseRepository;

    private CaseImport caseImport(String key) {
        return new CaseImport(key, "{\"actionCategory\":\"READ\"}", PolicyDecisionType.ALLOW, null, true, null);
    }

    @Test
    void creatingASecondSuiteWithTheSameNameAddsANewVersionRatherThanEditingTheFirst() {
        String name = "versioning-test-" + System.nanoTime();
        EvaluationSuite v1 = suiteService.create(new CreateSuiteRequest(name, "v1", List.of(caseImport("case-a"))),
                "admin");
        List<EvaluationCase> v1CasesBefore = caseRepository.findBySuiteIdOrderById(v1.getId());

        EvaluationSuite v2 = suiteService.create(
                new CreateSuiteRequest(name, "v2", List.of(caseImport("case-a"), caseImport("case-b"))), "admin");

        assertThat(v2.getVersion()).isEqualTo(v1.getVersion() + 1);
        assertThat(v2.getId()).isNotEqualTo(v1.getId());

        // v1's own row and its cases are completely untouched by v2's creation.
        EvaluationSuite v1Reloaded = suiteRepository.findById(v1.getId()).orElseThrow();
        assertThat(v1Reloaded.getStatus()).isEqualTo(EvaluationSuiteStatus.SUPERSEDED);
        assertThat(v1Reloaded.getChecksum()).isEqualTo(v1.getChecksum());
        List<EvaluationCase> v1CasesAfter = caseRepository.findBySuiteIdOrderById(v1.getId());
        assertThat(v1CasesAfter).hasSameSizeAs(v1CasesBefore);
        assertThat(v1CasesAfter.get(0).getChecksum()).isEqualTo(v1CasesBefore.get(0).getChecksum());

        assertThat(v2.getStatus()).isEqualTo(EvaluationSuiteStatus.ACTIVE);
        assertThat(caseRepository.findBySuiteIdOrderById(v2.getId())).hasSize(2);
    }

    @Test
    void resolvingWithNoExplicitVersionAlwaysGetsTheLatest() {
        String name = "versioning-latest-" + System.nanoTime();
        suiteService.create(new CreateSuiteRequest(name, "v1", List.of(caseImport("case-a"))), "admin");
        EvaluationSuite v2 = suiteService.create(new CreateSuiteRequest(name, "v2", List.of(caseImport("case-a"))),
                "admin");

        EvaluationSuite resolved = suiteService.resolveForRun(name, null);

        assertThat(resolved.getId()).isEqualTo(v2.getId());
    }

    @Test
    void resolvingAnExplicitOlderVersionStillWorksAfterANewerVersionExists() {
        String name = "versioning-explicit-" + System.nanoTime();
        EvaluationSuite v1 = suiteService.create(new CreateSuiteRequest(name, "v1", List.of(caseImport("case-a"))),
                "admin");
        suiteService.create(new CreateSuiteRequest(name, "v2", List.of(caseImport("case-a"))), "admin");

        EvaluationSuite resolved = suiteService.resolveForRun(name, 1);

        assertThat(resolved.getId()).isEqualTo(v1.getId());
    }
}
