package com.agentshield.policy;

import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.RiskLevel;
import com.agentshield.gateway.GatewayRequest;
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
@Table(name = "policy_decisions")
@Getter
@Setter
@NoArgsConstructor
public class PolicyDecision {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "gateway_request_id", nullable = false)
    private GatewayRequest gatewayRequest;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private PolicyDecisionType decision;

    @Column(name = "policy_version", length = 64)
    private String policyVersion;

    @Column(length = 4000)
    private String reason;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false, length = 32)
    private RiskLevel riskLevel;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
