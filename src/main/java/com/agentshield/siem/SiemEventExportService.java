package com.agentshield.siem;

import com.agentshield.approval.ApprovalRequestRepository;
import com.agentshield.common.ValidationException;
import com.agentshield.dlp.DlpFinding;
import com.agentshield.dlp.DlpFindingRepository;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.policy.PolicyDecision;
import com.agentshield.policy.PolicyDecisionRepository;
import com.agentshield.siem.SiemEventDtos.SiemEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

/**
 * Builds one flat {@link SiemEvent} per {@link GatewayRequest} in a date range — the SIEM/Splunk/
 * Elastic-friendly counterpart to {@code GovernanceReportService}'s AI-RMF-shaped export, reusing
 * the same "assemble from existing operational tables, no new source of truth" approach.
 */
@Service
public class SiemEventExportService {

    private static final int MAX_FINDINGS_PER_EVENT = 50;

    private final GatewayRequestRepository gatewayRequestRepository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final DlpFindingRepository dlpFindingRepository;
    private final ApprovalRequestRepository approvalRequestRepository;
    private final ObjectMapper objectMapper;

    public SiemEventExportService(GatewayRequestRepository gatewayRequestRepository,
            PolicyDecisionRepository policyDecisionRepository, DlpFindingRepository dlpFindingRepository,
            ApprovalRequestRepository approvalRequestRepository, ObjectMapper objectMapper) {
        this.gatewayRequestRepository = gatewayRequestRepository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.dlpFindingRepository = dlpFindingRepository;
        this.approvalRequestRepository = approvalRequestRepository;
        this.objectMapper = objectMapper;
    }

    public List<SiemEvent> export(Instant from, Instant to) {
        if (from == null || to == null || !from.isBefore(to)) {
            throw new ValidationException("from must be a timestamp strictly before to");
        }
        List<SiemEvent> events = new ArrayList<>();
        for (GatewayRequest request : gatewayRequestRepository.findByCreatedAtBetweenOrderByCreatedAtAsc(from, to)) {
            events.add(toEvent(request));
        }
        return events;
    }

    /** One JSON object per line, no wrapping array — the shape real SIEM bulk-ingest expects. */
    public String toNdjson(List<SiemEvent> events) {
        StringBuilder sb = new StringBuilder();
        for (SiemEvent event : events) {
            sb.append(writeJson(event)).append('\n');
        }
        return sb.toString();
    }

    private SiemEvent toEvent(GatewayRequest request) {
        PolicyDecision decision = policyDecisionRepository
                .findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc(request.getId()).orElse(null);

        List<String> findings = dlpFindingRepository
                .findByCorrelationIdOrderByCreatedAtAsc(request.getCorrelationId(), PageRequest.of(0, MAX_FINDINGS_PER_EVENT))
                .stream()
                .map(this::findingSummary)
                .toList();

        String approvalStatus = approvalRequestRepository.findByGatewayRequestId(request.getId())
                .map(a -> a.getStatus().name())
                .orElse(null);

        List<String> ruleIds = decision != null && decision.getRuleId() != null ? List.of(decision.getRuleId()) : List.of();

        return new SiemEvent(
                "agentshield.gateway_request",
                request.getCreatedAt(),
                request.getAgent().getId(),
                request.getTool() != null ? request.getTool().getName() : null,
                request.getActionName(),
                request.getTool() != null ? request.getTool().getName() : null,
                decision != null ? decision.getDecision().name() : null,
                decision != null ? decision.getRiskScore() : null,
                findings,
                approvalStatus,
                ruleIds,
                request.getCorrelationId());
    }

    /** Category + confidence only — never the indicator/offset detail an attacker could use to
     * reconstruct the matched value, and never the matched substring itself (that never leaves
     * the detector layer in the first place — see {@code DetectionMatch}). */
    private String findingSummary(DlpFinding finding) {
        return finding.getCategory().name() + ":" + finding.getConfidence().name();
    }

    private String writeJson(SiemEvent event) {
        try {
            return objectMapper.writeValueAsString(event);
        } catch (Exception e) {
            return "{}";
        }
    }
}
