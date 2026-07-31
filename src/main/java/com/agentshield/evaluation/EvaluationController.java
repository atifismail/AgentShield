package com.agentshield.evaluation;

import com.agentshield.evaluation.EvaluationDtos.CaseResponse;
import com.agentshield.evaluation.EvaluationDtos.CreateSuiteRequest;
import com.agentshield.evaluation.EvaluationDtos.ResultResponse;
import com.agentshield.evaluation.EvaluationDtos.RunDetailResponse;
import com.agentshield.evaluation.EvaluationDtos.RunResponse;
import com.agentshield.evaluation.EvaluationDtos.SuiteDetailResponse;
import com.agentshield.evaluation.EvaluationDtos.SuiteResponse;
import com.agentshield.evaluation.EvaluationDtos.TriggerRunRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/evaluations")
@Tag(name = "Policy evaluations", description = "Simulation only — no tool was invoked. Runs synthetic fixtures through the real pre-call policy/grant/MCP-consent components with zero tool forwarding (work package 4).")
public class EvaluationController {

    private final EvaluationSuiteService suiteService;
    private final EvaluationRunService runService;
    private final EvaluationCaseRepository caseRepository;

    public EvaluationController(EvaluationSuiteService suiteService, EvaluationRunService runService,
            EvaluationCaseRepository caseRepository) {
        this.suiteService = suiteService;
        this.runService = runService;
        this.caseRepository = caseRepository;
    }

    @PostMapping("/suites")
    @ResponseStatus(HttpStatus.CREATED)
    public SuiteResponse createSuite(@Valid @RequestBody CreateSuiteRequest request, Authentication authentication) {
        return toSuiteResponse(suiteService.create(request, actorName(authentication)));
    }

    @PostMapping("/suites/built-in")
    @ResponseStatus(HttpStatus.CREATED)
    public SuiteResponse createBuiltInSuite(Authentication authentication) {
        return toSuiteResponse(suiteService.createBuiltIn(actorName(authentication)));
    }

    @GetMapping("/suites")
    public List<SuiteResponse> listSuites() {
        return suiteService.list().stream().map(this::toSuiteResponse).toList();
    }

    @GetMapping("/suites/{id}")
    public SuiteDetailResponse getSuite(@PathVariable Long id) {
        EvaluationSuite suite = suiteService.get(id);
        List<CaseResponse> cases = suiteService.listCases(id).stream().map(CaseResponse::from).toList();
        return new SuiteDetailResponse(toSuiteResponse(suite), cases);
    }

    @PostMapping("/runs")
    @ResponseStatus(HttpStatus.CREATED)
    public RunResponse triggerRun(@Valid @RequestBody TriggerRunRequest request, Authentication authentication) {
        return RunResponse.from(runService.triggerRun(request, actorName(authentication)));
    }

    @GetMapping("/runs")
    public List<RunResponse> listRuns() {
        return runService.list().stream().map(RunResponse::from).toList();
    }

    @GetMapping("/runs/{id}")
    public RunDetailResponse getRun(@PathVariable Long id) {
        EvaluationRun run = runService.get(id);
        Map<Long, String> caseKeysById = caseRepository.findBySuiteIdOrderById(run.getSuiteId()).stream()
                .collect(java.util.stream.Collectors.toMap(EvaluationCase::getId, EvaluationCase::getCaseKey));
        List<ResultResponse> results = runService.results(id).stream()
                .map(r -> new ResultResponse(r.getId(), r.getCaseId(),
                        caseKeysById.getOrDefault(r.getCaseId(), "unknown"), r.getActualDecision(),
                        r.getActualRuleId(), r.getResultStatus(), r.getRedactedReason(), r.getDurationMillis(),
                        r.getEvaluatorVersion()))
                .toList();
        return new RunDetailResponse(RunResponse.from(run), results);
    }

    private SuiteResponse toSuiteResponse(EvaluationSuite suite) {
        int caseCount = suiteService.listCases(suite.getId()).size();
        return new SuiteResponse(suite.getId(), suite.getName(), suite.getVersion(), suite.getStatus(),
                suite.getDescription(), suite.getChecksum(), caseCount, suite.getCreatedBy(), suite.getCreatedAt());
    }

    private String actorName(Authentication authentication) {
        return authentication == null ? "system" : authentication.getName();
    }
}
