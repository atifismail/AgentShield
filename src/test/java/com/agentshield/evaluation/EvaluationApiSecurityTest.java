package com.agentshield.evaluation;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.audit.AuditEventRepository;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.evaluation.EvaluationDtos.CaseImport;
import com.agentshield.evaluation.EvaluationDtos.CreateSuiteRequest;
import com.agentshield.evaluation.EvaluationDtos.SuiteResponse;
import com.agentshield.evaluation.EvaluationDtos.TriggerRunRequest;
import com.agentshield.support.AbstractIntegrationTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 4, "Authorization and
 * audit tests cover all mutation/run endpoints."
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EvaluationApiSecurityTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AuditEventRepository auditEventRepository;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    private CreateSuiteRequest request(String name) {
        var caseImport = new CaseImport("case-a",
                "{\"actionCategory\":\"READ\",\"toolGroup\":\"db\",\"agentAllowedToolGroups\":\"db\","
                        + "\"toolApprovalStatus\":\"APPROVED\"}",
                PolicyDecisionType.ALLOW, null, true, null);
        return new CreateSuiteRequest(name, null, List.of(caseImport));
    }

    @Test
    void adminCanCreateASuiteAndTriggerARunAndBothAreAudited() {
        String name = "api-sec-suite-" + System.nanoTime();
        ResponseEntity<SuiteResponse> createResponse = admin.postForEntity(
                "http://localhost:" + port + "/api/evaluations/suites", request(name), SuiteResponse.class);
        assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        var runRequest = new TriggerRunRequest(name, null);
        ResponseEntity<EvaluationDtos.RunResponse> runResponse = admin.postForEntity(
                "http://localhost:" + port + "/api/evaluations/runs", runRequest, EvaluationDtos.RunResponse.class);
        assertThat(runResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(runResponse.getBody().passedCases()).isEqualTo(1);

        assertThat(auditEventRepository.findAll()).anyMatch(e -> e.getEventType().equals("evaluation_suite.created"));
        assertThat(auditEventRepository.findAll()).anyMatch(e -> e.getEventType().equals("evaluation_run.completed"));
    }

    @Test
    void anonymousCannotCreateASuite() {
        TestRestTemplate anon = new TestRestTemplate();
        ResponseEntity<String> response = anon.postForEntity(
                "http://localhost:" + port + "/api/evaluations/suites", request("anon-suite-" + System.nanoTime()),
                String.class);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.CREATED);
    }

    @Test
    void anonymousCannotTriggerARun() {
        TestRestTemplate anon = new TestRestTemplate();
        ResponseEntity<String> response = anon.postForEntity(
                "http://localhost:" + port + "/api/evaluations/runs", new TriggerRunRequest("anything", null),
                String.class);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.CREATED);
    }

    @Test
    void anonymousCannotCreateTheBuiltInSuiteEither() {
        TestRestTemplate anon = new TestRestTemplate();
        ResponseEntity<String> response = anon.postForEntity(
                "http://localhost:" + port + "/api/evaluations/suites/built-in", null, String.class);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.CREATED);
    }
}
