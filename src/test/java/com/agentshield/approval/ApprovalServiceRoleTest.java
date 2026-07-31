package com.agentshield.approval;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.agentshield.agent.Agent;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ApprovalStatus;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.gateway.GatewayService;
import com.agentshield.policy.PolicyDecisionRepository;
import com.agentshield.security.UserRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 3, "Required tests":
 * wrong role cannot approve; the documented ADMIN-always-passes override; no-profile-matched
 * falls back to the pre-existing ADMIN/APPROVER behavior unchanged.
 */
class ApprovalServiceRoleTest {

    private final ApprovalRequestRepository repository = Mockito.mock(ApprovalRequestRepository.class);
    private final PolicyDecisionRepository policyDecisionRepository = Mockito.mock(PolicyDecisionRepository.class);
    private final GatewayService gatewayService = Mockito.mock(GatewayService.class);
    private final AuditService auditService = Mockito.mock(AuditService.class);
    private final ApprovalService service = new ApprovalService(repository, policyDecisionRepository, gatewayService,
            auditService, new ObjectMapper());

    private Authentication authWithRole(UserRole role) {
        return new TestingAuthenticationToken("user", "pw", List.of(new SimpleGrantedAuthority("ROLE_" + role.name())));
    }

    private ApprovalRequest pendingApprovalRoutedTo(UserRole assignedRole) {
        Agent agent = new Agent();
        agent.setId(1L);
        GatewayRequest gatewayRequest = new GatewayRequest();
        gatewayRequest.setAgent(agent);
        gatewayRequest.setTool(null); // early-return path, no ToolForwarder needed

        ApprovalRequest approval = new ApprovalRequest();
        approval.setId(10L);
        approval.setStatus(ApprovalStatus.PENDING);
        approval.setGatewayRequest(gatewayRequest);
        approval.setAssignedRole(assignedRole);
        when(repository.findByIdForUpdate(10L)).thenReturn(Optional.of(approval));
        return approval;
    }

    @Test
    void wrongRoleCannotApproveARoutedApproval() {
        pendingApprovalRoutedTo(UserRole.SECURITY_ANALYST);

        assertThatThrownBy(() -> service.approve(10L, "approver-1", authWithRole(UserRole.APPROVER)))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void theAssignedRoleCanApproveARoutedApproval() {
        pendingApprovalRoutedTo(UserRole.SECURITY_ANALYST);

        var response = service.approve(10L, "analyst-1", authWithRole(UserRole.SECURITY_ANALYST));

        assertThat(response.status()).isEqualTo(ApprovalStatus.APPROVED);
    }

    @Test
    void adminAlwaysPassesRegardlessOfTheAssignedRole() {
        pendingApprovalRoutedTo(UserRole.SECURITY_ANALYST);

        var response = service.approve(10L, "admin-1", authWithRole(UserRole.ADMIN));

        assertThat(response.status()).isEqualTo(ApprovalStatus.APPROVED);
    }

    @Test
    void noMatchingProfileFallsBackToAdminOrApproverUnchanged() {
        pendingApprovalRoutedTo(null);

        // SECURITY_ANALYST alone is not enough when no profile routed this approval — the
        // pre-existing ADMIN/APPROVER-only behavior must apply unchanged.
        assertThatThrownBy(() -> service.approve(10L, "analyst-1", authWithRole(UserRole.SECURITY_ANALYST)))
                .isInstanceOf(AccessDeniedException.class);

        var response = service.approve(10L, "approver-1", authWithRole(UserRole.APPROVER));
        assertThat(response.status()).isEqualTo(ApprovalStatus.APPROVED);
    }

    @Test
    void nullAuthenticationSkipsTheRoleCheckForInternalCallers() {
        pendingApprovalRoutedTo(UserRole.SECURITY_ANALYST);

        var response = service.approve(10L, "internal-caller", null);

        assertThat(response.status()).isEqualTo(ApprovalStatus.APPROVED);
    }

    @Test
    void wrongRoleCannotRejectARoutedApprovalEither() {
        pendingApprovalRoutedTo(UserRole.TOOL_OWNER);

        assertThatThrownBy(() -> service.reject(10L, "approver-1", authWithRole(UserRole.APPROVER)))
                .isInstanceOf(AccessDeniedException.class);
    }
}
