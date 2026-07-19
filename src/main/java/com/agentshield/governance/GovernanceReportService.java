package com.agentshield.governance;

import com.agentshield.agent.AgentRepository;
import com.agentshield.approval.ApprovalRequest;
import com.agentshield.approval.ApprovalRequestRepository;
import com.agentshield.common.ApprovalStatus;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.ValidationException;
import com.agentshield.governance.GovernanceReportDtos.AgentSummary;
import com.agentshield.governance.GovernanceReportDtos.ApprovalRecords;
import com.agentshield.governance.GovernanceReportDtos.ApprovalSummary;
import com.agentshield.governance.GovernanceReportDtos.ApprovedTools;
import com.agentshield.governance.GovernanceReportDtos.DeniedActionSummary;
import com.agentshield.governance.GovernanceReportDtos.DeniedActions;
import com.agentshield.governance.GovernanceReportDtos.DriftEventSummary;
import com.agentshield.governance.GovernanceReportDtos.DriftEvents;
import com.agentshield.governance.GovernanceReportDtos.GovernanceReport;
import com.agentshield.governance.GovernanceReportDtos.IncidentSummary;
import com.agentshield.governance.GovernanceReportDtos.Incidents;
import com.agentshield.governance.GovernanceReportDtos.PolicyVersionSummary;
import com.agentshield.governance.GovernanceReportDtos.PolicyVersions;
import com.agentshield.governance.GovernanceReportDtos.RegisteredAgents;
import com.agentshield.governance.GovernanceReportDtos.ToolSummary;
import com.agentshield.incident.Incident;
import com.agentshield.incident.IncidentRepository;
import com.agentshield.policy.PolicyDecision;
import com.agentshield.policy.PolicyDecisionRepository;
import com.agentshield.policy.PolicyRepository;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolVersion;
import com.agentshield.tool.ToolVersionRepository;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import org.springframework.stereotype.Service;

/**
 * Assembles a governance evidence report for a date range (improvement_plan.md P2 "AI RMF
 * Governance Mapping"). Read-only: every field is derived from existing operational tables, so
 * this adds no new source of truth and no retention concerns beyond what's already stored.
 */
@Service
public class GovernanceReportService {

    private final AgentRepository agentRepository;
    private final ToolRepository toolRepository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final ApprovalRequestRepository approvalRequestRepository;
    private final ToolVersionRepository toolVersionRepository;
    private final IncidentRepository incidentRepository;
    private final PolicyRepository policyRepository;

    public GovernanceReportService(AgentRepository agentRepository, ToolRepository toolRepository,
            PolicyDecisionRepository policyDecisionRepository, ApprovalRequestRepository approvalRequestRepository,
            ToolVersionRepository toolVersionRepository, IncidentRepository incidentRepository,
            PolicyRepository policyRepository) {
        this.agentRepository = agentRepository;
        this.toolRepository = toolRepository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.approvalRequestRepository = approvalRequestRepository;
        this.toolVersionRepository = toolVersionRepository;
        this.incidentRepository = incidentRepository;
        this.policyRepository = policyRepository;
    }

    public GovernanceReport generate(Instant from, Instant to) {
        if (from == null || to == null || !from.isBefore(to)) {
            throw new ValidationException("from must be a timestamp strictly before to");
        }

        var agents = agentRepository.findAll().stream()
                .map(a -> new AgentSummary(a.getName(), a.getStatus().name(), a.getOwner(),
                        a.getAllowedToolGroups(), a.getCreatedAt()))
                .toList();

        var tools = toolRepository.findByApprovalStatus(ToolApprovalStatus.APPROVED).stream()
                .map(GovernanceReportService::toToolSummary)
                .toList();

        var deniedActions = policyDecisionRepository
                .findByDecisionAndCreatedAtBetweenOrderByCreatedAtDesc(PolicyDecisionType.DENY, from, to).stream()
                .map(GovernanceReportService::toDeniedActionSummary)
                .toList();

        var approvalsInRange = approvalRequestRepository.findByCreatedAtBetweenOrderByCreatedAtDesc(from, to);
        var approvalSummaries = approvalsInRange.stream()
                .map(GovernanceReportService::toApprovalSummary)
                .toList();
        long approvedCount = approvalsInRange.stream().filter(a -> a.getStatus() == ApprovalStatus.APPROVED).count();
        long rejectedCount = approvalsInRange.stream().filter(a -> a.getStatus() == ApprovalStatus.REJECTED).count();
        long expiredCount = approvalsInRange.stream().filter(a -> a.getStatus() == ApprovalStatus.EXPIRED).count();

        var driftEvents = toolVersionRepository.findByDetectedAtBetweenOrderByDetectedAtDesc(from, to).stream()
                .map(GovernanceReportService::toDriftEventSummary)
                .toList();

        var incidents = incidentRepository.findByCreatedAtBetweenOrderByCreatedAtDesc(from, to).stream()
                .map(GovernanceReportService::toIncidentSummary)
                .toList();

        var policyVersions = policyRepository.findAllByOrderByNameAscVersionDesc().stream()
                .map(p -> new PolicyVersionSummary(p.getName(), p.getVersion(), p.isEnabled(), p.getMode().name(),
                        p.getCreatedBy(), p.getCreatedAt()))
                .toList();

        return new GovernanceReport(from, to, Instant.now(),
                new RegisteredAgents(agents.size(), agents),
                new ApprovedTools(tools.size(), tools),
                new DeniedActions(deniedActions.size(), deniedActions),
                new ApprovalRecords(approvalSummaries.size(), approvedCount, rejectedCount, expiredCount, approvalSummaries),
                new DriftEvents(driftEvents.size(), driftEvents),
                new Incidents(incidents.size(), incidents),
                new PolicyVersions(policyVersions));
    }

    public String renderMarkdown(GovernanceReport report) {
        DateTimeFormatter fmt = DateTimeFormatter.ISO_INSTANT;
        StringBuilder sb = new StringBuilder();
        sb.append("# AgentShield Governance Evidence Report\n\n");
        sb.append("Period: ").append(fmt.format(report.from())).append(" to ").append(fmt.format(report.to())).append("\n\n");
        sb.append("Generated: ").append(fmt.format(report.generatedAt())).append("\n\n");
        sb.append("Mapped to NIST AI RMF govern/map/measure/manage functions.\n\n");

        sb.append("## Govern: Registered Agents (").append(report.registeredAgents().totalCount()).append(")\n\n");
        sb.append("| Name | Status | Owner | Allowed Tool Groups | Created |\n|---|---|---|---|---|\n");
        for (var a : report.registeredAgents().agents()) {
            sb.append("| ").append(a.name()).append(" | ").append(a.status()).append(" | ")
                    .append(nullToDash(a.owner())).append(" | ").append(nullToDash(a.allowedToolGroups()))
                    .append(" | ").append(fmt.format(a.createdAt())).append(" |\n");
        }

        sb.append("\n## Map: Approved Tools (").append(report.approvedTools().totalCount()).append(")\n\n");
        sb.append("| Name | Type | Group | Source | Created |\n|---|---|---|---|---|\n");
        for (var t : report.approvedTools().tools()) {
            sb.append("| ").append(t.name()).append(" | ").append(t.type()).append(" | ").append(t.toolGroup())
                    .append(" | ").append(t.sourceType()).append(" | ").append(fmt.format(t.createdAt())).append(" |\n");
        }

        sb.append("\n## Measure: Denied Actions In Period (").append(report.deniedActions().count()).append(")\n\n");
        sb.append("| Request | Agent | Tool | Category | Risk | Reason | When |\n|---|---|---|---|---|---|---|\n");
        for (var d : report.deniedActions().actions()) {
            sb.append("| ").append(d.gatewayRequestId()).append(" | ").append(d.agentName()).append(" | ")
                    .append(nullToDash(d.toolName())).append(" | ").append(d.actionCategory()).append(" | ")
                    .append(d.riskLevel()).append(" (").append(d.riskScore()).append(") | ").append(d.reason())
                    .append(" | ").append(fmt.format(d.createdAt())).append(" |\n");
        }

        sb.append("\n## Manage: Approval Records In Period (").append(report.approvalRecords().count())
                .append(" total; ").append(report.approvalRecords().approvedCount()).append(" approved, ")
                .append(report.approvalRecords().rejectedCount()).append(" rejected, ")
                .append(report.approvalRecords().expiredCount()).append(" expired)\n\n");
        sb.append("| ID | Request | Status | Requested By | Decided By | When |\n|---|---|---|---|---|---|\n");
        for (var a : report.approvalRecords().approvals()) {
            String decidedBy = a.approvedBy() != null ? a.approvedBy() : a.rejectedBy();
            sb.append("| ").append(a.id()).append(" | ").append(a.gatewayRequestId()).append(" | ")
                    .append(a.status()).append(" | ").append(nullToDash(a.requestedBy())).append(" | ")
                    .append(nullToDash(decidedBy)).append(" | ").append(fmt.format(a.createdAt())).append(" |\n");
        }

        sb.append("\n## Measure: Tool Drift Events In Period (").append(report.driftEvents().count()).append(")\n\n");
        sb.append("| Tool | Version | Status | Detected |\n|---|---|---|---|\n");
        for (var d : report.driftEvents().events()) {
            sb.append("| ").append(d.toolName()).append(" | ").append(d.toolVersionId()).append(" | ")
                    .append(d.status()).append(" | ").append(fmt.format(d.detectedAt())).append(" |\n");
        }

        sb.append("\n## Manage: Incidents Opened In Period (").append(report.incidents().count()).append(")\n\n");
        sb.append("| ID | Title | Severity | Status | Opened |\n|---|---|---|---|---|\n");
        for (var i : report.incidents().incidents()) {
            sb.append("| ").append(i.id()).append(" | ").append(i.title()).append(" | ").append(i.severity())
                    .append(" | ").append(i.status()).append(" | ").append(fmt.format(i.createdAt())).append(" |\n");
        }

        sb.append("\n## Govern: Policy Versions In Force\n\n");
        sb.append("| Name | Version | Enabled | Mode | Created By | Created |\n|---|---|---|---|---|---|\n");
        for (var p : report.policyVersions().policies()) {
            sb.append("| ").append(p.name()).append(" | ").append(p.version()).append(" | ").append(p.enabled())
                    .append(" | ").append(p.mode()).append(" | ").append(nullToDash(p.createdBy())).append(" | ")
                    .append(fmt.format(p.createdAt())).append(" |\n");
        }

        return sb.toString();
    }

    private static String nullToDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private static ToolSummary toToolSummary(Tool t) {
        return new ToolSummary(t.getName(), t.getType().name(), t.getToolGroup(), t.getSourceType().name(),
                t.getApprovalStatus().name(), t.getCreatedAt());
    }

    private static DeniedActionSummary toDeniedActionSummary(PolicyDecision d) {
        var req = d.getGatewayRequest();
        return new DeniedActionSummary(req.getId(), req.getAgent().getName(),
                req.getTool() != null ? req.getTool().getName() : null, req.getActionCategory().name(),
                d.getReason(), d.getRiskLevel().name(), d.getRiskScore(), d.getCreatedAt());
    }

    private static ApprovalSummary toApprovalSummary(ApprovalRequest a) {
        return new ApprovalSummary(a.getId(), a.getGatewayRequest().getId(), a.getStatus().name(),
                a.getRequestedBy(), a.getApprovedBy(), a.getRejectedBy(), a.getCreatedAt());
    }

    private static DriftEventSummary toDriftEventSummary(ToolVersion v) {
        return new DriftEventSummary(v.getTool().getName(), v.getId(), v.getStatus().name(), v.getDetectedAt());
    }

    private static IncidentSummary toIncidentSummary(Incident i) {
        return new IncidentSummary(i.getId(), i.getTitle(), i.getSeverity().name(), i.getStatus().name(), i.getCreatedAt());
    }
}
