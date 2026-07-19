package com.agentshield.policy;

import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.mcp.McpConsentService;
import com.agentshield.risk.DetectionResult;
import com.agentshield.tool.ToolApprovalStatus;
import org.springframework.stereotype.Component;

/**
 * The default Java-based policy evaluator. Implements the 10 default rules from
 * PROJECT_PLAN.md section 10 plus one added since (rule 11, MCP consent — see below), evaluated
 * in order — the first matching rule decides the outcome; if none match, database-backed
 * overrides are consulted, and if none of those match either, the request is ALLOWed. Every
 * non-allow outcome carries a human-readable reason (AGENTS.md rule 7).
 *
 * Rules 7 and 8 inspect the tool's *response* and can only be evaluated after the call
 * has been forwarded, so they live in {@link #evaluateResponse}, not {@link #evaluateRequest}.
 */
@Component
public class PolicyEngine implements PolicyEvaluator {

    static final int DEFAULT_MAX_PAYLOAD_BYTES = 262_144; // 256 KiB

    private final PolicyOverrideRepository overrideRepository;
    private final McpConsentService mcpConsentService;

    public PolicyEngine(PolicyOverrideRepository overrideRepository, McpConsentService mcpConsentService) {
        this.overrideRepository = overrideRepository;
        this.mcpConsentService = mcpConsentService;
    }

    @Override
    public PolicyOutcome evaluateRequest(PolicyEvaluationContext ctx) {
        PolicyOutcome outcome;
        if ((outcome = denyDisabledAgent(ctx)) != null) {
            return outcome;
        }
        if ((outcome = denyUnapprovedTool(ctx)) != null) {
            return outcome;
        }
        if ((outcome = denySchemaDrift(ctx)) != null) {
            return outcome;
        }
        if ((outcome = denyProdDestructiveWithoutApproval(ctx)) != null) {
            return outcome;
        }
        if ((outcome = requireApprovalForProdWrite(ctx)) != null) {
            return outcome;
        }
        if ((outcome = requireApprovalForExternalTransfer(ctx)) != null) {
            return outcome;
        }
        if ((outcome = denyOutsideAllowedGroup(ctx)) != null) {
            return outcome;
        }
        if ((outcome = denyOversizedPayload(ctx)) != null) {
            return outcome;
        }
        if ((outcome = denyMissingMcpConsent(ctx)) != null) {
            return outcome;
        }
        if ((outcome = evaluateOverrides(ctx)) != null) {
            return outcome;
        }
        return PolicyOutcome.allow();
    }

    /**
     * Only reached when every fixed safety rule above would otherwise ALLOW — an override can
     * add extra restriction (or a scoped extra allowance an operator explicitly configured) but
     * can never weaken the fixed rules, since those are checked first and unconditionally.
     */
    PolicyOutcome evaluateOverrides(PolicyEvaluationContext ctx) {
        for (PolicyOverride override : overrideRepository.findActiveOrderByPriority()) {
            if (override.matches(ctx)) {
                return new PolicyOutcome(override.getDecision(), override.getReason(), "override-" + override.getId());
            }
        }
        return null;
    }

    /** Rule 1: deny disabled agents. */
    PolicyOutcome denyDisabledAgent(PolicyEvaluationContext ctx) {
        if (!ctx.agent().isEnabled()) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "agent '" + ctx.agent().getName() + "' is disabled", "deny-disabled-agent");
        }
        return null;
    }

    /** Rule 2: deny unapproved tools (pending or rejected — drift is handled separately by rule 3). */
    PolicyOutcome denyUnapprovedTool(PolicyEvaluationContext ctx) {
        ToolApprovalStatus status = ctx.tool().getApprovalStatus();
        if (status == ToolApprovalStatus.PENDING || status == ToolApprovalStatus.REJECTED) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "tool '" + ctx.tool().getName() + "' is not approved (status=" + status + ")",
                    "deny-unapproved-tool");
        }
        return null;
    }

    /** Rule 3: deny tools with schema/description drift. */
    PolicyOutcome denySchemaDrift(PolicyEvaluationContext ctx) {
        if (ctx.tool().getApprovalStatus() == ToolApprovalStatus.DRIFTED || ctx.tool().hasDrift()) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "tool '" + ctx.tool().getName() + "' has schema/description drift and requires re-approval",
                    "deny-schema-drift");
        }
        return null;
    }

    /** Rule 4: deny production destructive actions outright — they are never auto-approved. */
    PolicyOutcome denyProdDestructiveWithoutApproval(PolicyEvaluationContext ctx) {
        if (ctx.isProd() && ctx.actionCategory() == ActionCategory.DESTRUCTIVE) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "production destructive actions require prior human approval and cannot be auto-allowed",
                    "deny-prod-destructive-without-approval");
        }
        return null;
    }

    /** Rule 5: production write actions require human approval. */
    PolicyOutcome requireApprovalForProdWrite(PolicyEvaluationContext ctx) {
        if (ctx.isProd() && ctx.actionCategory() == ActionCategory.WRITE) {
            return new PolicyOutcome(PolicyDecisionType.APPROVAL_REQUIRED,
                    "production write actions require human approval", "require-approval-prod-write");
        }
        return null;
    }

    /** Rule 6: external data transfer requires human approval. */
    PolicyOutcome requireApprovalForExternalTransfer(PolicyEvaluationContext ctx) {
        if (ctx.actionCategory() == ActionCategory.EXTERNAL_TRANSFER) {
            return new PolicyOutcome(PolicyDecisionType.APPROVAL_REQUIRED,
                    "external data transfer requires human approval", "require-approval-external-transfer");
        }
        return null;
    }

    /**
     * Rule 9: deny agents calling tools outside their allowed groups. An agent with no
     * allowed tool groups configured is denied everything (least privilege / deny-by-default).
     */
    PolicyOutcome denyOutsideAllowedGroup(PolicyEvaluationContext ctx) {
        var allowedGroups = ctx.agent().allowedToolGroupSet();
        if (!allowedGroups.contains(ctx.tool().getToolGroup())) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "agent '" + ctx.agent().getName() + "' is not allowed to call tool group '"
                            + ctx.tool().getToolGroup() + "'",
                    "deny-tool-outside-allowed-group");
        }
        return null;
    }

    /** Rule 10: deny requests above the maximum payload size. */
    PolicyOutcome denyOversizedPayload(PolicyEvaluationContext ctx) {
        int max = ctx.maxPayloadSizeBytes() > 0 ? ctx.maxPayloadSizeBytes() : DEFAULT_MAX_PAYLOAD_BYTES;
        if (ctx.payloadSizeBytes() > max) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "request payload (" + ctx.payloadSizeBytes() + " bytes) exceeds the maximum allowed size of "
                            + max + " bytes",
                    "deny-oversized-payload");
        }
        return null;
    }

    /**
     * Rule 11: for an MCP-backed tool, the calling agent must hold an ACTIVE, unexpired
     * {@link com.agentshield.mcp.McpConsent} grant scoped to this server (and, if the grant is
     * that specific, this tool/action category) — the direct confused-deputy fix
     * (design-mcp-authorization.md §5). A tool being APPROVED is necessary but not sufficient for
     * MCP-backed tools. Non-MCP tools are unaffected.
     */
    PolicyOutcome denyMissingMcpConsent(PolicyEvaluationContext ctx) {
        if (!ctx.tool().isMcpBacked()) {
            return null;
        }
        boolean hasConsent = mcpConsentService.hasActiveConsent(ctx.agent().getId(), ctx.tool().getMcpServerId(),
                ctx.tool().getMcpToolName(), ctx.actionCategory());
        if (!hasConsent) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "agent '" + ctx.agent().getName() + "' has no active MCP consent for tool '"
                            + ctx.tool().getName() + "'",
                    "deny-missing-mcp-consent");
        }
        return null;
    }

    /**
     * Rules 7 and 8: scan a tool's response before it is returned to the agent.
     *
     * @param destinationIsExternal true when the originating action category is EXTERNAL_TRANSFER —
     *                               that is what PROJECT_PLAN.md means by "destination is external".
     */
    @Override
    public PolicyOutcome evaluateResponse(boolean destinationIsExternal, DetectionResult secretResult,
            DetectionResult injectionResult) {
        if (destinationIsExternal && secretResult.matched()) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "response contains a secret-like value (" + String.join(", ", secretResult.matchedIndicators())
                            + ") and the destination is external", "deny-secret-external-transfer");
        }
        if (injectionResult.matched()) {
            return new PolicyOutcome(PolicyDecisionType.DENY,
                    "tool response contains a prompt-injection pattern ("
                            + String.join(", ", injectionResult.matchedIndicators()) + ")",
                    "deny-prompt-injection-response");
        }
        return PolicyOutcome.allow();
    }
}
