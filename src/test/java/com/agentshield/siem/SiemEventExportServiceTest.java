package com.agentshield.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.agent.Agent;
import com.agentshield.approval.ApprovalRequestRepository;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.GatewayRequestStatus;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.RiskLevel;
import com.agentshield.common.ValidationException;
import com.agentshield.dlp.DlpFindingRepository;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.policy.PolicyDecision;
import com.agentshield.policy.PolicyDecisionRepository;
import com.agentshield.tool.Tool;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

/**
 * Plain unit test (no Spring context), matching {@code ToolProvenanceServiceTest}'s style — proves
 * the exported event schema is shaped correctly and never leaks a raw finding value, without
 * needing a real database.
 */
class SiemEventExportServiceTest {

    private final GatewayRequestRepository gatewayRequestRepository = Mockito.mock(GatewayRequestRepository.class);
    private final PolicyDecisionRepository policyDecisionRepository = Mockito.mock(PolicyDecisionRepository.class);
    private final DlpFindingRepository dlpFindingRepository = Mockito.mock(DlpFindingRepository.class);
    private final ApprovalRequestRepository approvalRequestRepository = Mockito.mock(ApprovalRequestRepository.class);
    private final SiemEventExportService service = new SiemEventExportService(gatewayRequestRepository,
            policyDecisionRepository, dlpFindingRepository, approvalRequestRepository, new ObjectMapper());

    private GatewayRequest gatewayRequest(String correlationId) {
        Agent agent = new Agent();
        agent.setId(1L);
        agent.setName("test-agent");
        Tool tool = new Tool();
        tool.setId(2L);
        tool.setName("mock-git");

        GatewayRequest request = new GatewayRequest();
        request.setId(10L);
        request.setCorrelationId(correlationId);
        request.setAgent(agent);
        request.setTool(tool);
        request.setActionName("commit");
        request.setActionCategory(ActionCategory.WRITE);
        request.setStatus(GatewayRequestStatus.COMPLETED);
        request.setCreatedAt(Instant.now());
        return request;
    }

    @Test
    void exportRejectsAFromNotBeforeTo() {
        Instant now = Instant.now();
        assertThatThrownBy(() -> service.export(now, now.minusSeconds(60)))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void exportMapsGatewayRequestToFlatSiemEventSchema() {
        GatewayRequest request = gatewayRequest("corr-1");
        Instant from = request.getCreatedAt().minusSeconds(60);
        Instant to = request.getCreatedAt().plusSeconds(60);
        Mockito.when(gatewayRequestRepository.findByCreatedAtBetweenOrderByCreatedAtAsc(from, to))
                .thenReturn(List.of(request));

        PolicyDecision decision = new PolicyDecision();
        decision.setDecision(PolicyDecisionType.ALLOW);
        decision.setRiskScore(10);
        decision.setRiskLevel(RiskLevel.LOW);
        decision.setRuleId(null);
        Mockito.when(policyDecisionRepository.findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc(10L))
                .thenReturn(Optional.of(decision));
        Mockito.when(dlpFindingRepository.findByCorrelationIdOrderByCreatedAtAsc(Mockito.eq("corr-1"), Mockito.any()))
                .thenReturn(new PageImpl<>(List.of()));
        Mockito.when(approvalRequestRepository.findByGatewayRequestId(10L)).thenReturn(Optional.empty());

        List<SiemEventDtos.SiemEvent> events = service.export(from, to);

        assertThat(events).hasSize(1);
        SiemEventDtos.SiemEvent event = events.get(0);
        assertThat(event.eventType()).isEqualTo("agentshield.gateway_request");
        assertThat(event.agentId()).isEqualTo(1L);
        assertThat(event.toolName()).isEqualTo("mock-git");
        assertThat(event.operation()).isEqualTo("commit");
        assertThat(event.decision()).isEqualTo("ALLOW");
        assertThat(event.riskScore()).isEqualTo(10);
        assertThat(event.traceId()).isEqualTo("corr-1");
        assertThat(event.policyRuleIds()).isEmpty();
    }

    @Test
    void ndjsonOutputIsOneJsonObjectPerLineWithNoWrappingArray() {
        var event = new SiemEventDtos.SiemEvent("agentshield.gateway_request", Instant.now(), 1L, "mock-git",
                "commit", "mock-git", "ALLOW", 10, List.of(), null, List.of(), "corr-1");
        String ndjson = service.toNdjson(List.of(event, event));
        String[] lines = ndjson.strip().split("\n");
        assertThat(lines).hasSize(2);
        assertThat(lines[0]).startsWith("{").endsWith("}");
    }

    @Test
    void findingsNeverIncludeTheRawMatchedSubstringOnlyCategoryAndConfidence() {
        var finding = Mockito.mock(com.agentshield.dlp.DlpFinding.class);
        Mockito.when(finding.getCategory()).thenReturn(com.agentshield.risk.DetectorCategory.CREDENTIAL);
        Mockito.when(finding.getConfidence()).thenReturn(com.agentshield.risk.Confidence.HIGH);

        GatewayRequest request = gatewayRequest("corr-2");
        Instant from = request.getCreatedAt().minusSeconds(60);
        Instant to = request.getCreatedAt().plusSeconds(60);
        Mockito.when(gatewayRequestRepository.findByCreatedAtBetweenOrderByCreatedAtAsc(from, to))
                .thenReturn(List.of(request));
        Mockito.when(policyDecisionRepository.findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc(10L))
                .thenReturn(Optional.empty());
        Page<com.agentshield.dlp.DlpFinding> page = new PageImpl<>(List.of(finding));
        Mockito.when(dlpFindingRepository.findByCorrelationIdOrderByCreatedAtAsc(Mockito.eq("corr-2"), Mockito.any()))
                .thenReturn(page);
        Mockito.when(approvalRequestRepository.findByGatewayRequestId(10L)).thenReturn(Optional.empty());

        List<SiemEventDtos.SiemEvent> events = service.export(from, to);

        assertThat(events).hasSize(1);
        assertThat(events.get(0).findings()).containsExactly("CREDENTIAL:HIGH");
    }
}
