package com.agentshield.evaluation;

import com.agentshield.common.PolicyDecisionType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;

public final class EvaluationDtos {

    private EvaluationDtos() {
    }

    public record CaseImport(
            @NotBlank @Size(max = 255) String caseKey,
            @NotBlank @Size(max = 20_000) String inputFixtureJson,
            @NotNull PolicyDecisionType expectedDecision,
            @Size(max = 128) String expectedRuleId,
            Boolean expectNoToolCall,
            @Size(max = 500) String tags
    ) {
    }

    public record CreateSuiteRequest(
            @NotBlank @Size(max = 255) String name,
            @Size(max = 2000) String description,
            @NotEmpty @Size(max = 500) List<@Valid CaseImport> cases
    ) {
    }

    public record TriggerRunRequest(
            @NotBlank String suiteName,
            /** Null means "the latest ACTIVE version". */
            Integer suiteVersion
    ) {
    }

    public record SuiteResponse(
            Long id,
            String name,
            int version,
            EvaluationSuiteStatus status,
            String description,
            String checksum,
            int caseCount,
            String createdBy,
            Instant createdAt
    ) {
    }

    public record CaseResponse(
            Long id,
            String caseKey,
            String inputFixtureJson,
            PolicyDecisionType expectedDecision,
            String expectedRuleId,
            boolean expectNoToolCall,
            String tags
    ) {
        public static CaseResponse from(EvaluationCase c) {
            return new CaseResponse(c.getId(), c.getCaseKey(), c.getInputFixtureJson(), c.getExpectedDecision(),
                    c.getExpectedRuleId(), c.isExpectNoToolCall(), c.getTags());
        }
    }

    public record SuiteDetailResponse(SuiteResponse suite, List<CaseResponse> cases) {
    }

    public record RunResponse(
            Long id,
            Long suiteId,
            int suiteVersion,
            String policyConfigFingerprint,
            String triggeredBy,
            Instant startedAt,
            Instant completedAt,
            int totalCases,
            int passedCases,
            int failedCases,
            int errorCases
    ) {
        public static RunResponse from(EvaluationRun run) {
            return new RunResponse(run.getId(), run.getSuiteId(), run.getSuiteVersion(),
                    run.getPolicyConfigFingerprint(), run.getTriggeredBy(), run.getStartedAt(), run.getCompletedAt(),
                    run.getTotalCases(), run.getPassedCases(), run.getFailedCases(), run.getErrorCases());
        }
    }

    public record ResultResponse(
            Long id,
            Long caseId,
            String caseKey,
            PolicyDecisionType actualDecision,
            String actualRuleId,
            EvaluationResultStatus resultStatus,
            String redactedReason,
            long durationMillis,
            String evaluatorVersion
    ) {
    }

    public record RunDetailResponse(RunResponse run, List<ResultResponse> results) {
    }
}
