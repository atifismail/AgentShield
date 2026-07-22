package com.agentshield.dlp;

import com.agentshield.risk.DetectionMatch;
import com.agentshield.risk.DetectionResult;
import com.agentshield.risk.PiiDetector;
import com.agentshield.risk.PromptInjectionDetector;
import com.agentshield.risk.SecretDetector;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Runs {@link SecretDetector}, {@link PiiDetector}, and {@link PromptInjectionDetector} against a
 * piece of content, resolves the applicable {@link ClassificationProfile}, and returns the
 * combined outcome plus persisted {@link DlpFinding} rows — the DLP-specific counterpart to how
 * {@code GatewayService.executeAndScan} already scans tool responses, but reusable for any
 * content stage (inbound prompt, tool argument, tool result, RAG chunk).
 */
@Service
public class DlpScanService {

    private final SecretDetector secretDetector;
    private final PiiDetector piiDetector;
    private final PromptInjectionDetector injectionDetector;
    private final ClassificationProfileRepository profileRepository;
    private final DlpFindingRepository findingRepository;
    private final RedactionService redactionService;
    private final ObjectMapper objectMapper;

    public DlpScanService(SecretDetector secretDetector, PiiDetector piiDetector,
            PromptInjectionDetector injectionDetector, ClassificationProfileRepository profileRepository,
            DlpFindingRepository findingRepository, RedactionService redactionService, ObjectMapper objectMapper) {
        this.secretDetector = secretDetector;
        this.piiDetector = piiDetector;
        this.injectionDetector = injectionDetector;
        this.profileRepository = profileRepository;
        this.findingRepository = findingRepository;
        this.redactionService = redactionService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public DlpScanResult scan(String text, ContentStage stage, String correlationId) {
        if (text == null || text.isBlank()) {
            return new DlpScanResult(DlpAction.ALLOW, text, List.of());
        }

        ClassificationProfile profile = profileRepository.findFirstActive().orElseGet(this::builtInDefaultProfile);
        List<Pattern> customPatterns = compileCustomPatterns(profile);

        DetectionResult secretResult = profile.isDetectSecrets() ? secretDetector.scan(text) : DetectionResult.CLEAN;
        DetectionResult piiResult = profile.isDetectPii() ? piiDetector.scan(text, customPatterns) : DetectionResult.CLEAN;
        DetectionResult injectionResult = profile.isDetectPromptInjection()
                ? injectionDetector.scan(text)
                : DetectionResult.CLEAN;

        List<DetectionMatch> allMatches = new ArrayList<>();
        allMatches.addAll(secretResult.matches());
        allMatches.addAll(piiResult.matches());
        allMatches.addAll(injectionResult.matches());

        DlpAction action = allMatches.isEmpty() ? DlpAction.ALLOW : profile.getDefaultAction();

        for (DetectionMatch match : allMatches) {
            persistFinding(correlationId, stage, match, action, profile);
        }

        String outputText = (action == DlpAction.REDACT || action == DlpAction.TOKENIZE)
                ? redactionService.redact(text, allMatches)
                : text;

        return new DlpScanResult(action, outputText, allMatches);
    }

    /**
     * Used when no operator has configured a profile yet — fails closed (BLOCK on any match, all
     * detectors on) rather than silently allowing everything through until someone sets one up,
     * consistent with this codebase's fail-closed default (see {@code docs/architecture.md}).
     */
    private ClassificationProfile builtInDefaultProfile() {
        ClassificationProfile profile = new ClassificationProfile();
        profile.setName("built-in-default");
        profile.setDetectSecrets(true);
        profile.setDetectPii(true);
        profile.setDetectPromptInjection(true);
        profile.setDefaultAction(DlpAction.BLOCK);
        return profile;
    }

    private List<Pattern> compileCustomPatterns(ClassificationProfile profile) {
        String json = profile.getCustomPatternsJson();
        if (json == null || json.isBlank()) {
            return List.of();
        }
        List<Pattern> patterns = new ArrayList<>();
        try {
            for (var node : objectMapper.readTree(json)) {
                try {
                    patterns.add(Pattern.compile(node.asText()));
                } catch (PatternSyntaxException e) {
                    // Skip a single invalid operator-entered regex rather than failing the whole scan.
                }
            }
        } catch (Exception e) {
            return List.of();
        }
        return patterns;
    }

    private void persistFinding(String correlationId, ContentStage stage, DetectionMatch match, DlpAction action,
            ClassificationProfile profile) {
        DlpFinding finding = new DlpFinding();
        finding.setCorrelationId(correlationId);
        finding.setContentStage(stage);
        finding.setIndicator(match.indicator());
        finding.setCategory(match.category());
        finding.setConfidence(match.confidence());
        finding.setOffset(match.offset());
        finding.setLength(match.length());
        finding.setActionTaken(action);
        finding.setClassificationProfileId(profile.getId());
        findingRepository.save(finding);
    }
}
