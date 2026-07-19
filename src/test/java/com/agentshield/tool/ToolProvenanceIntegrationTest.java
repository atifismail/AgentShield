package com.agentshield.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.common.ConflictException;
import com.agentshield.support.AbstractIntegrationTest;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * design-tool-supply-chain-provenance.md §13, against the real database and Spring-wired
 * {@code ToolService}/{@code ToolProvenanceService} — proves the checksum row is created
 * automatically at registration time and that the approval-time trust-policy gate is real,
 * end to end, not just at the mocked-service level ({@link ToolProvenanceServiceTest}).
 */
@SpringBootTest
class ToolProvenanceIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private ToolService toolService;
    @Autowired
    private ToolProvenanceRepository provenanceRepository;
    @Autowired
    private ToolVersionRepository versionRepository;
    @Autowired
    private ProvenanceProperties properties;

    @AfterEach
    void resetTrustPolicy() {
        properties.setRequireSignatureFor(Set.of());
    }

    @Test
    void registeringAToolAutomaticallyRecordsAnUnverifiedChecksum() {
        var request = new ToolDtos.RegisterToolRequest("provenance-test-" + System.nanoTime(), ToolType.SAAS, "saas",
                "https://example.com/v1", "owner", "DEV", "a test tool", "{}");

        Tool tool = toolService.register(request);

        var version = versionRepository.findByToolIdOrderByDetectedAtDesc(tool.getId()).get(0);
        var provenance = provenanceRepository.findByToolVersionId(version.getId()).orElseThrow();
        assertThat(provenance.getVerificationMode()).isEqualTo(VerificationMode.UNVERIFIED);
        assertThat(provenance.getChecksum()).isEqualTo(version.getHash());
    }

    @Test
    void approvalIsRejectedWhenTrustPolicyRequiresASignatureThatWasNeverSubmitted() {
        properties.setRequireSignatureFor(Set.of(ToolSourceType.CUSTOM_HTTP));
        var request = new ToolDtos.RegisterToolRequest("provenance-gate-test-" + System.nanoTime(), ToolType.SAAS,
                "saas", "https://example.com/v1", "owner", "DEV", "a test tool", "{}");
        Tool tool = toolService.register(request);

        assertThatThrownBy(() -> toolService.approveLatestVersion(tool.getId(), "admin"))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("requires a verified signature");
    }

    @Test
    void approvalSucceedsWhenTrustPolicyDoesNotCoverThisSourceType() {
        properties.setRequireSignatureFor(Set.of(ToolSourceType.MCP));
        var request = new ToolDtos.RegisterToolRequest("provenance-exempt-test-" + System.nanoTime(), ToolType.SAAS,
                "saas", "https://example.com/v1", "owner", "DEV", "a test tool", "{}");
        Tool tool = toolService.register(request);

        Tool approved = toolService.approveLatestVersion(tool.getId(), "admin");

        assertThat(approved.getApprovalStatus()).isEqualTo(ToolApprovalStatus.APPROVED);
    }
}
