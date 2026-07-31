package com.agentshield.evaluation;

import com.agentshield.common.ActionCategory;
import com.agentshield.grant.GrantTransitionMode;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRiskTier;

/**
 * The parsed shape of {@code EvaluationCase.inputFixtureJson} — a fully synthetic description of
 * an agent/tool/request the evaluation engine builds entirely in memory, never a real captured
 * request (work package 4). Every field is optional except {@code actionCategory}; the engine
 * applies safe defaults for everything else. Fields are boxed so "not specified" (null) is
 * distinguishable from an explicit false/zero.
 */
public record EvaluationCaseFixture(
        /** When true, the engine reports {@code deny-tool-not-registered} without building a tool at all. */
        Boolean unknownTool,
        Long agentId,
        Boolean agentEnabled,
        String agentAllowedToolGroups,
        Long toolId,
        String toolName,
        ToolApprovalStatus toolApprovalStatus,
        /** When true, the tool's approved/current hash are made to differ (schema drift). */
        Boolean toolHasDrift,
        String toolGroup,
        ToolRiskTier toolRiskTier,
        Long toolMcpServerId,
        String toolMcpToolName,
        ActionCategory actionCategory,
        String targetEnvironment,
        Integer payloadSizeBytes,
        Integer maxPayloadSizeBytes,
        /** Null means "use the deployment's real configured transition mode". */
        GrantTransitionMode grantTransitionMode,
        /** Synthetic tool-argument text to run through the real DLP scanner (never real captured content). */
        String dlpInputText
) {
}
