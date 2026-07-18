package com.agentshield.gateway;

import com.agentshield.agent.Agent;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.GatewayRequestStatus;
import com.agentshield.tool.Tool;
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
@Table(name = "gateway_requests")
@Getter
@Setter
@NoArgsConstructor
public class GatewayRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "correlation_id", nullable = false, unique = true, length = 64)
    private String correlationId;

    @Column(name = "user_id")
    private String userId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "agent_id", nullable = false)
    private Agent agent;

    @ManyToOne
    @JoinColumn(name = "tool_id")
    private Tool tool;

    @Column(name = "action_name", nullable = false)
    private String actionName;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_category", nullable = false, length = 32)
    private ActionCategory actionCategory;

    @Column(name = "target_environment", length = 64)
    private String targetEnvironment;

    @Column(name = "request_body_hash", length = 128)
    private String requestBodyHash;

    @Column(name = "request_summary", length = 4000)
    private String requestSummary;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private GatewayRequestStatus status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
