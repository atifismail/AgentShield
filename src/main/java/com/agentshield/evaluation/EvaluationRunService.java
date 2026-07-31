package com.agentshield.evaluation;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.evaluation.EvaluationDtos.TriggerRunRequest;
import com.agentshield.grant.GrantProperties;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Orchestrates one evaluation run: loads a suite's cases, evaluates each through
 * {@link EvaluationEngine} (never a real tool call), and persists the run/result rows
 * (agentshield_policy_evidence_execution_plan_2026-07-30.md work package 4).
 */
@Service
public class EvaluationRunService {

    private final EvaluationSuiteService suiteService;
    private final EvaluationRunRepository runRepository;
    private final EvaluationResultRepository resultRepository;
    private final EvaluationEngine engine;
    private final GrantProperties grantProperties;
    private final AuditService auditService;

    public EvaluationRunService(EvaluationSuiteService suiteService, EvaluationRunRepository runRepository,
            EvaluationResultRepository resultRepository, EvaluationEngine engine, GrantProperties grantProperties,
            AuditService auditService) {
        this.suiteService = suiteService;
        this.runRepository = runRepository;
        this.resultRepository = resultRepository;
        this.engine = engine;
        this.grantProperties = grantProperties;
        this.auditService = auditService;
    }

    @Transactional
    public EvaluationRun triggerRun(TriggerRunRequest request, String triggeredBy) {
        EvaluationSuite suite = suiteService.resolveForRun(request.suiteName(), request.suiteVersion());
        List<EvaluationCase> cases = suiteService.listCases(suite.getId());

        EvaluationRun run = new EvaluationRun();
        run.setSuiteId(suite.getId());
        run.setSuiteVersion(suite.getVersion());
        run.setPolicyConfigFingerprint("grants-transition-mode=" + grantProperties.getTransitionMode());
        run.setTriggeredBy(triggeredBy);
        run.setStartedAt(Instant.now());
        run.setTotalCases(cases.size());
        run = runRepository.save(run);

        int passed = 0;
        int failed = 0;
        int errored = 0;
        for (EvaluationCase evaluationCase : cases) {
            EvaluationResult result = engine.evaluate(run, evaluationCase);
            resultRepository.save(result);
            switch (result.getResultStatus()) {
                case PASS -> passed++;
                case FAIL -> failed++;
                case ERROR -> errored++;
            }
        }

        run.setPassedCases(passed);
        run.setFailedCases(failed);
        run.setErrorCases(errored);
        run.setCompletedAt(Instant.now());

        auditService.record(null, "evaluation_run.completed", ActorType.USER, triggeredBy, null, null,
                AuditSeverity.INFO,
                "evaluation run " + run.getId() + " against suite '" + suite.getName() + "' v" + suite.getVersion()
                        + ": " + passed + " passed, " + failed + " failed, " + errored + " errored",
                Map.of("runId", String.valueOf(run.getId()), "suiteId", String.valueOf(suite.getId())));
        return run;
    }

    public EvaluationRun get(Long id) {
        return runRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("evaluation run " + id + " not found"));
    }

    public List<EvaluationRun> list() {
        return runRepository.findAllByOrderByStartedAtDesc();
    }

    public List<EvaluationResult> results(Long runId) {
        return resultRepository.findByRunIdOrderById(runId);
    }
}
