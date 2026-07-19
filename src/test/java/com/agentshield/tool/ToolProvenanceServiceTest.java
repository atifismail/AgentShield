package com.agentshield.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ConflictException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * design-tool-supply-chain-provenance.md §13. Uses a mocked {@link SignatureVerifier} rather
 * than the real Sigstore-backed one — the real success path needs genuine Sigstore
 * infrastructure and a signed artifact, neither reproducible offline; this covers
 * {@link ToolProvenanceService}'s own orchestration logic deterministically, matching
 * {@code PolicyEngineTest}'s plain-unit-test style for the same reason.
 */
class ToolProvenanceServiceTest {

    private final ToolProvenanceRepository provenanceRepository = Mockito.mock(ToolProvenanceRepository.class);
    private final ToolRepository toolRepository = Mockito.mock(ToolRepository.class);
    private final ToolVersionRepository versionRepository = Mockito.mock(ToolVersionRepository.class);
    private final SignatureVerifier signatureVerifier = Mockito.mock(SignatureVerifier.class);
    private final ProvenanceProperties properties = new ProvenanceProperties();
    private final AuditService auditService = Mockito.mock(AuditService.class);
    private final ToolProvenanceService service = new ToolProvenanceService(provenanceRepository, toolRepository,
            versionRepository, signatureVerifier, properties, auditService);

    private Tool tool(ToolSourceType sourceType) {
        Tool tool = new Tool();
        tool.setId(1L);
        tool.setName("test-tool");
        tool.setSourceType(sourceType);
        tool.setApprovalStatus(ToolApprovalStatus.PENDING);
        return tool;
    }

    private ToolVersion version(Tool tool) {
        ToolVersion version = new ToolVersion();
        version.setId(10L);
        version.setTool(tool);
        version.setHash("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".substring(0, 64));
        return version;
    }

    @Test
    void recordChecksumCreatesAnUnverifiedRowUsingTheVersionsExistingHash() {
        ToolVersion version = version(tool(ToolSourceType.CUSTOM_HTTP));
        Mockito.when(provenanceRepository.save(Mockito.any())).thenAnswer(inv -> inv.getArgument(0));

        ToolProvenance provenance = service.recordChecksum(version);

        assertThat(provenance.getVerificationMode()).isEqualTo(VerificationMode.UNVERIFIED);
        assertThat(provenance.getChecksum()).isEqualTo(version.getHash());
        assertThat(provenance.getChecksumAlgorithm()).isEqualTo("SHA-256");
    }

    @Test
    void requireSignatureIfPolicyMandatesAllowsWhenSourceTypeNotInPolicy() {
        properties.setRequireSignatureFor(Set.of());
        Tool tool = tool(ToolSourceType.MCP);
        ToolVersion version = version(tool);

        assertThatCode(() -> service.requireSignatureIfPolicyMandates(tool, version)).doesNotThrowAnyException();
    }

    @Test
    void requireSignatureIfPolicyMandatesRejectsWhenNoProvenanceRecordExists() {
        properties.setRequireSignatureFor(Set.of(ToolSourceType.MCP));
        Tool tool = tool(ToolSourceType.MCP);
        ToolVersion version = version(tool);
        Mockito.when(provenanceRepository.findByToolVersionId(version.getId())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.requireSignatureIfPolicyMandates(tool, version))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("requires a verified signature");
    }

    @Test
    void requireSignatureIfPolicyMandatesRejectsWhenProvenanceIsOnlyChecksumPinned() {
        properties.setRequireSignatureFor(Set.of(ToolSourceType.MCP));
        Tool tool = tool(ToolSourceType.MCP);
        ToolVersion version = version(tool);
        ToolProvenance unverified = new ToolProvenance();
        unverified.setVerificationMode(VerificationMode.UNVERIFIED);
        Mockito.when(provenanceRepository.findByToolVersionId(version.getId())).thenReturn(Optional.of(unverified));

        assertThatThrownBy(() -> service.requireSignatureIfPolicyMandates(tool, version))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void requireSignatureIfPolicyMandatesAllowsWhenSignatureVerified() {
        properties.setRequireSignatureFor(Set.of(ToolSourceType.MCP));
        Tool tool = tool(ToolSourceType.MCP);
        ToolVersion version = version(tool);
        ToolProvenance verified = new ToolProvenance();
        verified.setVerificationMode(VerificationMode.SIGNATURE_VERIFIED);
        Mockito.when(provenanceRepository.findByToolVersionId(version.getId())).thenReturn(Optional.of(verified));

        assertThatCode(() -> service.requireSignatureIfPolicyMandates(tool, version)).doesNotThrowAnyException();
    }

    @Test
    void builtInToolIsNeverSubjectToRequireSignatureForRegardlessOfPolicy() {
        // Policy would require it for every source type, including (hypothetically) BUILT_IN —
        // but requiresSignature() excludes BUILT_IN unconditionally.
        properties.setRequireSignatureFor(Set.of(ToolSourceType.BUILT_IN, ToolSourceType.MCP));
        Tool tool = tool(ToolSourceType.BUILT_IN);
        ToolVersion version = version(tool);

        // No provenance lookup should even be needed to allow this — but stub it empty to prove
        // the BUILT_IN exemption is checked before ever consulting a provenance record.
        Mockito.when(provenanceRepository.findByToolVersionId(Mockito.any())).thenReturn(Optional.empty());

        assertThatCode(() -> service.requireSignatureIfPolicyMandates(tool, version)).doesNotThrowAnyException();
        Mockito.verifyNoInteractions(provenanceRepository);
    }

    @Test
    void verifySignatureRecordsSuccessAndDoesNotAlterApprovalStatus() {
        Tool tool = tool(ToolSourceType.MCP);
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        ToolVersion version = version(tool);
        ToolProvenance existing = new ToolProvenance();
        existing.setToolVersion(version);
        Mockito.when(toolRepository.findById(tool.getId())).thenReturn(Optional.of(tool));
        Mockito.when(versionRepository.findByToolIdOrderByDetectedAtDesc(tool.getId())).thenReturn(List.of(version));
        Mockito.when(provenanceRepository.findByToolVersionId(version.getId())).thenReturn(Optional.of(existing));
        Mockito.when(signatureVerifier.verify(Mockito.any(), Mockito.eq("bundle-json"), Mockito.eq("me@example.com"),
                Mockito.eq("https://issuer.example.com")))
                .thenReturn(SignatureVerifier.VerificationResult.success("me@example.com", "https://issuer.example.com"));

        ToolProvenance result = service.verifySignature(tool.getId(), "bundle-json", "me@example.com",
                "https://issuer.example.com", "security-analyst-1");

        assertThat(result.getVerificationMode()).isEqualTo(VerificationMode.SIGNATURE_VERIFIED);
        assertThat(result.getCertificateIdentity()).isEqualTo("me@example.com");
        assertThat(tool.getApprovalStatus()).isEqualTo(ToolApprovalStatus.APPROVED);
    }

    @Test
    void verifySignatureFailureForcesApprovalStatusToDriftedAndPersistsIt() {
        Tool tool = tool(ToolSourceType.MCP);
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        ToolVersion version = version(tool);
        ToolProvenance existing = new ToolProvenance();
        existing.setToolVersion(version);
        Mockito.when(toolRepository.findById(tool.getId())).thenReturn(Optional.of(tool));
        Mockito.when(versionRepository.findByToolIdOrderByDetectedAtDesc(tool.getId())).thenReturn(List.of(version));
        Mockito.when(provenanceRepository.findByToolVersionId(version.getId())).thenReturn(Optional.of(existing));
        Mockito.when(signatureVerifier.verify(Mockito.any(), Mockito.anyString(), Mockito.any(), Mockito.any()))
                .thenReturn(SignatureVerifier.VerificationResult.failure("certificate identity does not match"));

        ToolProvenance result = service.verifySignature(tool.getId(), "bundle-json", "attacker@evil.example.com",
                "https://issuer.example.com", "security-analyst-1");

        assertThat(result.getVerificationMode()).isEqualTo(VerificationMode.SIGNATURE_FAILED);
        assertThat(tool.getApprovalStatus()).isEqualTo(ToolApprovalStatus.DRIFTED);
        // The regression this guards: verifySignature() must load its own managed Tool entity
        // (via toolRepository, inside its own transaction) rather than mutate one handed in by
        // the caller — otherwise the DRIFTED change is never actually persisted.
        Mockito.verify(toolRepository).save(tool);
    }

    @Test
    void revokeForcesApprovalStatusToDrifted() {
        Tool tool = tool(ToolSourceType.MCP);
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        ToolVersion version = version(tool);
        ToolProvenance provenance = new ToolProvenance();
        provenance.setId(5L);
        provenance.setToolVersion(version);
        provenance.setVerificationMode(VerificationMode.SIGNATURE_VERIFIED);
        Mockito.when(provenanceRepository.findById(5L)).thenReturn(Optional.of(provenance));

        ToolProvenance result = service.revoke(5L, "signing key compromised", "security-analyst-1");

        assertThat(result.getVerificationMode()).isEqualTo(VerificationMode.REVOKED);
        assertThat(result.getVerificationDetails()).isEqualTo("signing key compromised");
        assertThat(tool.getApprovalStatus()).isEqualTo(ToolApprovalStatus.DRIFTED);
        Mockito.verify(toolRepository).save(tool);
    }
}
