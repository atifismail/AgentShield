package com.agentshield.web;

import com.agentshield.approval.ApprovalRequestRepository;
import com.agentshield.common.ApprovalStatus;
import com.agentshield.common.IncidentStatus;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.RiskLevel;
import com.agentshield.gateway.GatewayRequestRepository;
import com.agentshield.incident.IncidentRepository;
import com.agentshield.policy.PolicyDecision;
import com.agentshield.policy.PolicyDecisionRepository;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private static final DateTimeFormatter DAY_LABEL = DateTimeFormatter.ofPattern("MM-dd");

    private final GatewayRequestRepository gatewayRequestRepository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final ApprovalRequestRepository approvalRequestRepository;
    private final ToolRepository toolRepository;
    private final IncidentRepository incidentRepository;

    public DashboardController(GatewayRequestRepository gatewayRequestRepository,
            PolicyDecisionRepository policyDecisionRepository, ApprovalRequestRepository approvalRequestRepository,
            ToolRepository toolRepository, IncidentRepository incidentRepository) {
        this.gatewayRequestRepository = gatewayRequestRepository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.approvalRequestRepository = approvalRequestRepository;
        this.toolRepository = toolRepository;
        this.incidentRepository = incidentRepository;
    }

    @GetMapping({"/", "/dashboard"})
    public String dashboard(Model model) {
        Instant since24h = Instant.now().minusSeconds(24 * 3600);
        Instant since7d = Instant.now().minusSeconds(7 * 24 * 3600);

        List<PolicyDecision> recentDecisions = policyDecisionRepository.findByCreatedAtAfterOrderByCreatedAtAsc(since7d);

        long highRiskAgentCount = recentDecisions.stream()
                .filter(d -> d.getCreatedAt().isAfter(since24h))
                .filter(d -> d.getRiskLevel() == RiskLevel.HIGH || d.getRiskLevel() == RiskLevel.CRITICAL)
                .map(d -> d.getGatewayRequest().getAgent().getId())
                .distinct()
                .count();

        Map<String, Object> stats = Map.of(
                "requestCount", gatewayRequestRepository.countByCreatedAtAfter(since24h),
                "denyCount", policyDecisionRepository.countByDecisionAndCreatedAtAfter(PolicyDecisionType.DENY, since24h),
                "pendingApprovalCount", approvalRequestRepository.countByStatus(ApprovalStatus.PENDING),
                "highRiskAgentCount", highRiskAgentCount,
                "toolDriftCount", toolRepository.countByApprovalStatus(ToolApprovalStatus.DRIFTED),
                "openIncidentCount", incidentRepository.countByStatus(IncidentStatus.OPEN));

        model.addAttribute("pageTitle", "Dashboard");
        model.addAttribute("stats", stats);
        model.addAttribute("recentIncidents", incidentRepository.findTop5ByOrderByCreatedAtDesc());
        model.addAttribute("chartSeries", buildChartSeries(recentDecisions));
        return "dashboard/index";
    }

    private Map<String, Object> buildChartSeries(List<PolicyDecision> decisions) {
        Map<String, long[]> byDay = new LinkedHashMap<>();
        for (int i = 6; i >= 0; i--) {
            String label = LocalDate.now(ZoneOffset.UTC).minusDays(i).format(DAY_LABEL);
            byDay.put(label, new long[3]); // allow, deny, approvalRequired
        }
        for (PolicyDecision decision : decisions) {
            String label = decision.getCreatedAt().atZone(ZoneOffset.UTC).toLocalDate().format(DAY_LABEL);
            long[] bucket = byDay.get(label);
            if (bucket == null) {
                continue;
            }
            switch (decision.getDecision()) {
                case ALLOW -> bucket[0]++;
                case DENY -> bucket[1]++;
                case APPROVAL_REQUIRED -> bucket[2]++;
            }
        }
        List<String> labels = new ArrayList<>();
        List<Long> allow = new ArrayList<>();
        List<Long> deny = new ArrayList<>();
        List<Long> approval = new ArrayList<>();
        byDay.forEach((label, counts) -> {
            labels.add(label);
            allow.add(counts[0]);
            deny.add(counts[1]);
            approval.add(counts[2]);
        });
        return Map.of("labels", labels, "allow", allow, "deny", deny, "approval", approval);
    }
}
