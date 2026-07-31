package com.agentshield.evaluation;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.TokenHasher;
import com.agentshield.evaluation.BuiltInEvaluationSuiteProvider.EvaluationCaseSpec;
import com.agentshield.evaluation.EvaluationDtos.CaseImport;
import com.agentshield.evaluation.EvaluationDtos.CreateSuiteRequest;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Versioned suite/case CRUD (agentshield_policy_evidence_execution_plan_2026-07-30.md work
 * package 4). There is no update-in-place endpoint at all — every {@link #create} call inserts a
 * brand-new {@code (name, version)} row; a suite "cannot be overwritten in place after a run"
 * because it can never be overwritten in place, full stop.
 */
@Service
public class EvaluationSuiteService {

    private final EvaluationSuiteRepository suiteRepository;
    private final EvaluationCaseRepository caseRepository;
    private final BuiltInEvaluationSuiteProvider builtInProvider;
    private final AuditService auditService;

    public EvaluationSuiteService(EvaluationSuiteRepository suiteRepository, EvaluationCaseRepository caseRepository,
            BuiltInEvaluationSuiteProvider builtInProvider, AuditService auditService) {
        this.suiteRepository = suiteRepository;
        this.caseRepository = caseRepository;
        this.builtInProvider = builtInProvider;
        this.auditService = auditService;
    }

    @Transactional
    public EvaluationSuite create(CreateSuiteRequest request, String createdBy) {
        int nextVersion = suiteRepository.findTopByNameOrderByVersionDesc(request.name())
                .map(s -> s.getVersion() + 1)
                .orElse(1);
        suiteRepository.findTopByNameOrderByVersionDesc(request.name())
                .ifPresent(previous -> {
                    previous.setStatus(EvaluationSuiteStatus.SUPERSEDED);
                    suiteRepository.save(previous);
                });

        List<EvaluationCase> cases = request.cases().stream()
                .map(this::toCaseEntity)
                .toList();
        String checksum = suiteChecksum(request.name(), nextVersion, cases);

        EvaluationSuite suite = new EvaluationSuite();
        suite.setName(request.name());
        suite.setVersion(nextVersion);
        suite.setStatus(EvaluationSuiteStatus.ACTIVE);
        suite.setDescription(request.description());
        suite.setChecksum(checksum);
        suite.setCreatedBy(createdBy);
        suite = suiteRepository.save(suite);

        for (EvaluationCase evaluationCase : cases) {
            evaluationCase.setSuiteId(suite.getId());
            caseRepository.save(evaluationCase);
        }

        auditService.record(null, "evaluation_suite.created", ActorType.USER, createdBy, null, null,
                AuditSeverity.INFO,
                "evaluation suite '" + suite.getName() + "' v" + suite.getVersion() + " created with "
                        + cases.size() + " case(s)",
                Map.of("suiteId", String.valueOf(suite.getId()), "version", String.valueOf(suite.getVersion())));
        return suite;
    }

    /** Idempotent per version — importing the same built-in content twice just creates a new,
     * checksum-identical-content version (still a distinct, reproducible row). */
    @Transactional
    public EvaluationSuite createBuiltIn(String createdBy) {
        builtInProvider.ensureGrantFixtures();
        List<CaseImport> imports = builtInProvider.buildCases().stream()
                .map(spec -> new CaseImport(spec.caseKey(), spec.inputFixtureJson(), spec.expectedDecision(),
                        spec.expectedRuleId(), true, "built-in"))
                .toList();
        return create(new CreateSuiteRequest(BuiltInEvaluationSuiteProvider.SUITE_NAME,
                "Shipped default-policy fixture suite — one case per required release fixture category.",
                imports), createdBy);
    }

    public List<EvaluationSuite> list() {
        return suiteRepository.findAll();
    }

    public EvaluationSuite get(Long id) {
        return suiteRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("evaluation suite " + id + " not found"));
    }

    public List<EvaluationCase> listCases(Long suiteId) {
        return caseRepository.findBySuiteIdOrderById(suiteId);
    }

    public EvaluationSuite resolveForRun(String name, Integer version) {
        Optional<EvaluationSuite> resolved = version == null
                ? suiteRepository.findTopByNameOrderByVersionDesc(name)
                : suiteRepository.findByNameAndVersion(name, version);
        return resolved.orElseThrow(() -> new ResourceNotFoundException(
                "no evaluation suite named '" + name + "'" + (version == null ? "" : " version " + version)));
    }

    private EvaluationCase toCaseEntity(CaseImport caseImport) {
        EvaluationCase entity = new EvaluationCase();
        entity.setCaseKey(caseImport.caseKey());
        entity.setInputFixtureJson(caseImport.inputFixtureJson());
        entity.setExpectedDecision(caseImport.expectedDecision());
        entity.setExpectedRuleId(caseImport.expectedRuleId());
        entity.setExpectNoToolCall(caseImport.expectNoToolCall() == null || caseImport.expectNoToolCall());
        entity.setTags(caseImport.tags());
        entity.setChecksum(caseChecksum(caseImport));
        return entity;
    }

    private String caseChecksum(CaseImport caseImport) {
        return TokenHasher.sha256Hex(caseImport.caseKey() + "|" + caseImport.inputFixtureJson() + "|"
                + caseImport.expectedDecision() + "|" + caseImport.expectedRuleId());
    }

    private String suiteChecksum(String name, int version, List<EvaluationCase> cases) {
        StringBuilder combined = new StringBuilder(name).append('|').append(version);
        for (EvaluationCase c : cases) {
            combined.append('|').append(c.getChecksum());
        }
        return TokenHasher.sha256Hex(combined.toString());
    }
}
