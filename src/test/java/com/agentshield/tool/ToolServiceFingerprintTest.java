package com.agentshield.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.agentshield.audit.AuditService;
import com.agentshield.gateway.OutboundEndpointValidator;
import com.agentshield.gateway.OutboundEndpointValidator.ValidationResult;
import com.agentshield.metrics.GatewayMetrics;
import com.agentshield.tool.ToolDtos.RegisterToolRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 1, "Required tests":
 * field-level review/drift state for description-only, input-only, output-only, and
 * risk/default-action-only changes, plus legacy-tool fingerprint-unavailable reporting. Pure
 * Mockito unit test — matches {@code ToolProvenanceServiceTest}'s style, no Spring context needed.
 */
class ToolServiceFingerprintTest {

    private final ToolRepository toolRepository = Mockito.mock(ToolRepository.class);
    private final ToolVersionRepository versionRepository = Mockito.mock(ToolVersionRepository.class);
    private final AuditService auditService = Mockito.mock(AuditService.class);
    private final OutboundEndpointValidator outboundEndpointValidator = Mockito.mock(OutboundEndpointValidator.class);
    private final GatewayMetrics metrics = Mockito.mock(GatewayMetrics.class);
    private final ToolProvenanceService provenanceService = Mockito.mock(ToolProvenanceService.class);
    private final ToolFingerprintService fingerprintService = new ToolFingerprintService(new ObjectMapper());

    private final ToolService service = new ToolService(toolRepository, versionRepository, auditService,
            outboundEndpointValidator, metrics, provenanceService, fingerprintService);

    private static final String DESCRIPTION = "Reads rows from the users table";
    private static final String INPUT_SCHEMA = "{\"type\":\"object\",\"properties\":{\"table\":{\"type\":\"string\"}}}";
    private static final String OUTPUT_SCHEMA = "{\"type\":\"object\",\"properties\":{\"rows\":{\"type\":\"array\"}}}";

    @BeforeEach
    void stubOutboundValidation() {
        when(outboundEndpointValidator.validate(any())).thenReturn(ValidationResult.allow());
        when(toolRepository.findByName(any())).thenReturn(Optional.empty());
        when(toolRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(versionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    /** An approved tool with a known baseline, wired into the mocked repositories by id. */
    private Tool approvedTool() {
        Tool tool = new Tool();
        tool.setId(1L);
        tool.setName("db-reader");
        tool.setSchemaJson(INPUT_SCHEMA);
        tool.setDescription(DESCRIPTION);
        tool.setOutputSchemaJson(OUTPUT_SCHEMA);
        String legacyHash = sha256LegacyFingerprint(INPUT_SCHEMA, DESCRIPTION);
        tool.setCurrentHash(legacyHash);
        tool.setApprovedHash(legacyHash);
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);

        ToolVersion approved = new ToolVersion();
        approved.setTool(tool);
        approved.setStatus(ToolVersionStatus.APPROVED);
        approved.setHash(legacyHash);
        approved.setDescriptionHash(fingerprintService.hashDescription(DESCRIPTION));
        approved.setInputSchemaHash(fingerprintService.hashJson(INPUT_SCHEMA));
        approved.setOutputSchemaHash(fingerprintService.hashJson(OUTPUT_SCHEMA));

        when(toolRepository.findById(1L)).thenReturn(Optional.of(tool));
        when(versionRepository.findByToolIdOrderByDetectedAtDescIdDesc(1L)).thenReturn(List.of(approved));
        return tool;
    }

    /** Mirrors ToolService's private legacy algorithm so the test fixture's baseline is realistic. */
    private String sha256LegacyFingerprint(String schemaJson, String description) {
        return com.agentshield.common.TokenHasher.sha256Hex(
                (schemaJson == null ? "" : schemaJson) + (description == null ? "" : description));
    }

    @Test
    void descriptionOnlyChangeAfterApprovalMarksToolDriftedAndRecordsANewVersion() {
        Tool tool = approvedTool();

        Tool result = service.refreshFingerprint(1L, INPUT_SCHEMA, "Reads and deletes rows from the users table",
                OUTPUT_SCHEMA, null, null);

        assertThat(result.getApprovalStatus()).isEqualTo(ToolApprovalStatus.DRIFTED);
        ArgumentCaptor<ToolVersion> captor = ArgumentCaptor.forClass(ToolVersion.class);
        Mockito.verify(versionRepository).save(captor.capture());
        assertThat(captor.getValue().getDescriptionHash())
                .isNotEqualTo(fingerprintService.hashDescription(DESCRIPTION));
        Mockito.verify(metrics).toolDriftDetected();
    }

    @Test
    void inputSchemaOnlyChangeAfterApprovalMarksToolDrifted() {
        approvedTool();
        String changedSchema = "{\"type\":\"object\",\"properties\":{\"table\":{\"type\":\"string\"},\"limit\":{\"type\":\"integer\"}}}";

        Tool result = service.refreshFingerprint(1L, changedSchema, DESCRIPTION, OUTPUT_SCHEMA, null, null);

        assertThat(result.getApprovalStatus()).isEqualTo(ToolApprovalStatus.DRIFTED);
        Mockito.verify(metrics).toolDriftDetected();
    }

    @Test
    void outputSchemaOnlyChangeAfterApprovalMarksToolDriftedEvenThoughTheLegacyHashIsUnaffected() {
        Tool tool = approvedTool();
        String changedOutput = "{\"type\":\"object\",\"properties\":{\"rows\":{\"type\":\"array\"},\"count\":{\"type\":\"integer\"}}}";
        String legacyHashBefore = tool.getCurrentHash();

        Tool result = service.refreshFingerprint(1L, INPUT_SCHEMA, DESCRIPTION, changedOutput, null, null);

        // The legacy combined hash never includes the output schema, so it is unchanged...
        assertThat(sha256LegacyFingerprint(INPUT_SCHEMA, DESCRIPTION)).isEqualTo(legacyHashBefore);
        // ...yet the tool must still be recognized as drifted, purely from the output-schema fingerprint.
        assertThat(result.getApprovalStatus()).isEqualTo(ToolApprovalStatus.DRIFTED);
        Mockito.verify(metrics).toolDriftDetected();
    }

    @Test
    void unchangedFieldsProduceNoDriftOnRefresh() {
        approvedTool();

        Tool result = service.refreshFingerprint(1L, INPUT_SCHEMA, DESCRIPTION, OUTPUT_SCHEMA, null, null);

        assertThat(result.getApprovalStatus()).isEqualTo(ToolApprovalStatus.APPROVED);
        Mockito.verify(versionRepository, Mockito.never()).save(any());
        Mockito.verify(metrics, Mockito.never()).toolDriftDetected();
    }

    @Test
    void riskTierOrDefaultActionChangeAloneDoesNotMarkToolDrifted() {
        Tool tool = approvedTool();

        Tool result = service.refreshFingerprint(1L, INPUT_SCHEMA, DESCRIPTION, OUTPUT_SCHEMA, ToolRiskTier.HIGH,
                ToolDefaultAction.DENY);

        assertThat(result.getApprovalStatus()).isEqualTo(ToolApprovalStatus.APPROVED);
        assertThat(result.getRiskTier()).isEqualTo(ToolRiskTier.HIGH);
        assertThat(result.getDefaultAction()).isEqualTo(ToolDefaultAction.DENY);
        Mockito.verify(versionRepository, Mockito.never()).save(any());
        Mockito.verify(metrics, Mockito.never()).toolDriftDetected();
    }

    @Test
    void legacyToolWithNullIndividualHashesReportsFingerprintStateLegacyUnavailable() {
        Tool tool = new Tool();
        tool.setDescriptionHash(null);
        tool.setInputSchemaHash(null);

        assertThat(tool.fingerprintState()).isEqualTo(ToolFingerprintState.LEGACY_UNAVAILABLE);
    }

    @Test
    void toolWithBothFieldHashesComputedReportsFingerprintStateAvailable() {
        Tool tool = new Tool();
        tool.setDescriptionHash("abc");
        tool.setInputSchemaHash("def");

        assertThat(tool.fingerprintState()).isEqualTo(ToolFingerprintState.AVAILABLE);
    }

    @Test
    void registeringANewToolComputesAllThreeIndependentHashesWhenDataIsSupplied() {
        var request = new RegisterToolRequest("new-tool", ToolType.SAAS, "saas", "https://example.com/api",
                "owner", "DEV", DESCRIPTION, INPUT_SCHEMA, OUTPUT_SCHEMA, ToolRiskTier.MODERATE,
                ToolDefaultAction.ALLOW);

        Tool tool = service.register(request);

        assertThat(tool.getDescriptionHash()).isEqualTo(fingerprintService.hashDescription(DESCRIPTION));
        assertThat(tool.getInputSchemaHash()).isEqualTo(fingerprintService.hashJson(INPUT_SCHEMA));
        assertThat(tool.getOutputSchemaHash()).isEqualTo(fingerprintService.hashJson(OUTPUT_SCHEMA));
        assertThat(tool.getRiskTier()).isEqualTo(ToolRiskTier.MODERATE);
        assertThat(tool.getDefaultAction()).isEqualTo(ToolDefaultAction.ALLOW);
        assertThat(tool.fingerprintState()).isEqualTo(ToolFingerprintState.AVAILABLE);
    }

    @Test
    void registeringWithoutRiskTierOrDefaultActionDefaultsToTheSafestValues() {
        var request = new RegisterToolRequest("new-tool-2", ToolType.SAAS, "saas", "https://example.com/api",
                "owner", "DEV", DESCRIPTION, INPUT_SCHEMA, null, null, null);

        Tool tool = service.register(request);

        assertThat(tool.getRiskTier()).isEqualTo(ToolRiskTier.UNCLASSIFIED);
        assertThat(tool.getDefaultAction()).isEqualTo(ToolDefaultAction.REVIEW);
        assertThat(tool.getOutputSchemaHash()).isNull();
    }
}
