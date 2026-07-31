package com.agentshield.approval;

import com.agentshield.common.ApprovalStatus;
import com.agentshield.gateway.GatewayRequest;
import com.agentshield.security.UserRole;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "approval_requests")
@Getter
@Setter
@NoArgsConstructor
public class ApprovalRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "gateway_request_id", nullable = false)
    private GatewayRequest gatewayRequest;

    @Column(name = "requested_by")
    private String requestedBy;

    @Column(name = "assigned_to")
    private String assignedTo;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private ApprovalStatus status = ApprovalStatus.PENDING;

    @Column(length = 4000)
    private String reason;

    @Column(name = "approved_by")
    private String approvedBy;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "rejected_by")
    private String rejectedBy;

    @Column(name = "rejected_at")
    private Instant rejectedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    /**
     * Set once, at creation, by {@link ApprovalProfileResolutionService} — never re-resolved
     * afterward, even if the matching profile is later disabled/changed (work package 3:
     * "never mutates a pending request's assigned routing after creation"). Null means no
     * profile matched; the legacy default expiration/unassigned-queue behavior applies.
     */
    @Column(name = "approval_profile_id")
    private Long approvalProfileId;

    @Enumerated(EnumType.STRING)
    @Column(name = "assigned_role", length = 32)
    private UserRole assignedRole;

    public boolean isPending() {
        return status == ApprovalStatus.PENDING;
    }

    public boolean isExpired(Instant now) {
        return isPending() && expiresAt != null && now.isAfter(expiresAt);
    }
}
