package com.agentshield.gateway;

import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.RiskLevel;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Map;

public final class GatewayDtos {

    private GatewayDtos() {
    }

    /**
     * Matches the request shape in PROJECT_PLAN.md section 9. The calling agent's identity comes
     * from the {@code Authorization: Bearer <agent-token>} header, not from {@code agentId} here —
     * that field is accepted for readability/logging but is not trusted for authentication.
     * {@code toolId} is the tool's registered {@code name}.
     */
    public record InvokeRequest(
            String agentId,
            @NotBlank String toolId,
            @NotBlank String action,
            @NotNull ActionCategory actionCategory,
            String targetEnvironment,
            JsonNode input,
            Map<String, Object> context
    ) {
    }

    public record InvokeResponse(
            PolicyDecisionType decision,
            RiskLevel riskLevel,
            String reason,
            Long approvalRequestId,
            JsonNode result
    ) {
        public static InvokeResponse allow(RiskLevel riskLevel, JsonNode result) {
            return new InvokeResponse(PolicyDecisionType.ALLOW, riskLevel, null, null, result);
        }

        public static InvokeResponse deny(RiskLevel riskLevel, String reason) {
            return new InvokeResponse(PolicyDecisionType.DENY, riskLevel, reason, null, null);
        }

        public static InvokeResponse approvalRequired(RiskLevel riskLevel, String reason, Long approvalRequestId) {
            return new InvokeResponse(PolicyDecisionType.APPROVAL_REQUIRED, riskLevel, reason, approvalRequestId, null);
        }
    }
}
