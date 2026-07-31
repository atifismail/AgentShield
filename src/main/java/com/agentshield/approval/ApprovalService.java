package com.agentshield.approval;

import com.agentshield.approval.ApprovalDtos.ApprovalResponse;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.ApprovalStatus;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ConflictException;
import com.agentshield.common.GatewayRequestStatus;
import com.agentshield.common.RiskLevel;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.gateway.GatewayDtos.InvokeResponse;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayService;
import com.agentshield.policy.PolicyDecisionRepository;
import com.agentshield.risk.RiskAssessment;
import com.agentshield.security.UserRole;
import com.agentshield.tool.Tool;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Human-in-the-loop approval queue. Approving an action executes it immediately against the
 * tool (the gateway does not ask the agent to retry) — this keeps the gateway stateless from
 * the agent's point of view and avoids needing to persist raw request payloads long-term.
 */
@Service
public class ApprovalService {

    private final ApprovalRequestRepository repository;
    private final PolicyDecisionRepository policyDecisionRepository;
    private final GatewayService gatewayService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    public ApprovalService(ApprovalRequestRepository repository, PolicyDecisionRepository policyDecisionRepository,
            GatewayService gatewayService, AuditService auditService, ObjectMapper objectMapper) {
        this.repository = repository;
        this.policyDecisionRepository = policyDecisionRepository;
        this.gatewayService = gatewayService;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
    }

    public ApprovalRequest get(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("approval " + id + " not found"));
    }

    public List<ApprovalRequest> listPending() {
        return repository.findByStatusOrderByCreatedAtAsc(ApprovalStatus.PENDING);
    }

    public List<ApprovalRequest> listAll() {
        return repository.findAllByOrderByCreatedAtDesc();
    }

    @Transactional
    public ApprovalResponse approve(Long id, String approvedBy, Authentication authentication) {
        ApprovalRequest approval = requirePending(id);
        requireAuthorizedRole(approval, authentication);
        approval.setStatus(ApprovalStatus.APPROVED);
        approval.setApprovedBy(approvedBy);
        approval.setApprovedAt(Instant.now());

        GatewayRequest gatewayRequest = approval.getGatewayRequest();
        Tool tool = gatewayRequest.getTool();

        auditService.record(gatewayRequest.getCorrelationId(), "approval.approved", ActorType.USER, approvedBy,
                gatewayRequest.getAgent().getId(), tool == null ? null : tool.getId(), AuditSeverity.INFO,
                "approval " + id + " approved by " + approvedBy, null);

        if (tool == null) {
            gatewayRequest.setStatus(GatewayRequestStatus.FAILED);
            return ApprovalResponse.from(approval,
                    InvokeResponse.deny(RiskLevel.LOW, "original tool reference is no longer available"));
        }

        JsonNode input = parseStoredInput(gatewayRequest.getRequestBodyJson());
        RiskAssessment preCallRisk = policyDecisionRepository.findTopByGatewayRequestIdOrderByCreatedAtDescIdDesc(gatewayRequest.getId())
                .map(d -> new RiskAssessment(d.getRiskScore(), d.getRiskLevel(), List.of()))
                .orElse(new RiskAssessment(0, RiskLevel.LOW, List.of()));

        InvokeResponse result = gatewayService.executeAndScan(gatewayRequest, tool, gatewayRequest.getActionCategory(),
                input, preCallRisk);
        return ApprovalResponse.from(approval, result);
    }

    @Transactional
    public ApprovalResponse reject(Long id, String rejectedBy, Authentication authentication) {
        ApprovalRequest approval = requirePending(id);
        requireAuthorizedRole(approval, authentication);
        approval.setStatus(ApprovalStatus.REJECTED);
        approval.setRejectedBy(rejectedBy);
        approval.setRejectedAt(Instant.now());

        GatewayRequest gatewayRequest = approval.getGatewayRequest();
        gatewayRequest.setStatus(GatewayRequestStatus.DENIED);

        Tool tool = gatewayRequest.getTool();
        auditService.record(gatewayRequest.getCorrelationId(), "approval.rejected", ActorType.USER, rejectedBy,
                gatewayRequest.getAgent().getId(), tool == null ? null : tool.getId(), AuditSeverity.WARNING,
                "approval " + id + " rejected by " + rejectedBy, null);
        return ApprovalResponse.from(approval);
    }

    /** Runs every minute; PENDING approvals past their {@code expiresAt} are marked EXPIRED. */
    @Scheduled(fixedDelayString = "PT1M")
    @Transactional
    public void expireOverdueApprovals() {
        Instant now = Instant.now();
        for (ApprovalRequest approval : repository.findByStatusOrderByCreatedAtAsc(ApprovalStatus.PENDING)) {
            if (approval.isExpired(now)) {
                approval.setStatus(ApprovalStatus.EXPIRED);
                GatewayRequest gatewayRequest = approval.getGatewayRequest();
                gatewayRequest.setStatus(GatewayRequestStatus.FAILED);
                Tool tool = gatewayRequest.getTool();
                auditService.record(gatewayRequest.getCorrelationId(), "approval.expired", ActorType.SYSTEM,
                        "scheduler", gatewayRequest.getAgent().getId(), tool == null ? null : tool.getId(),
                        AuditSeverity.WARNING, "approval " + approval.getId() + " expired without a decision", null);
            }
        }
    }

    /**
     * "The approving user must possess the assigned role. An ADMIN can always resolve an
     * approval as existing product policy permits" (work package 3). When no profile matched
     * this approval, the pre-existing behavior applies unchanged: ADMIN or APPROVER. Documented
     * override: ADMIN always passes, regardless of routing.
     */
    private void requireAuthorizedRole(ApprovalRequest approval, Authentication authentication) {
        if (authentication == null) {
            return;
        }
        if (hasRole(authentication, UserRole.ADMIN)) {
            return;
        }
        UserRole required = approval.getAssignedRole();
        if (required == null) {
            if (!hasRole(authentication, UserRole.APPROVER)) {
                throw new AccessDeniedException("only ADMIN or APPROVER may resolve an approval with no routing profile");
            }
            return;
        }
        if (!hasRole(authentication, required)) {
            throw new AccessDeniedException(
                    "approval " + approval.getId() + " is routed to role " + required + "; caller does not hold it");
        }
    }

    private boolean hasRole(Authentication authentication, UserRole role) {
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_" + role.name()));
    }

    private ApprovalRequest requirePending(Long id) {
        ApprovalRequest approval = repository.findByIdForUpdate(id)
                .orElseThrow(() -> new ResourceNotFoundException("approval " + id + " not found"));
        if (approval.isExpired(Instant.now()) && approval.isPending()) {
            approval.setStatus(ApprovalStatus.EXPIRED);
            throw new ConflictException("approval " + id + " expired before a decision was made");
        }
        if (!approval.isPending()) {
            throw new ConflictException("approval " + id + " is not pending (status=" + approval.getStatus() + ")");
        }
        return approval;
    }

    private JsonNode parseStoredInput(String requestBodyJson) {
        if (requestBodyJson == null || requestBodyJson.isBlank()) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(requestBodyJson);
        } catch (Exception e) {
            return objectMapper.createObjectNode();
        }
    }
}
