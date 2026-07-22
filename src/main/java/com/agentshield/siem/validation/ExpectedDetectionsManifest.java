package com.agentshield.siem.validation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;

/**
 * For each {@link com.agentshield.siem.AttackSimulatorService} scenario code, the alert name(s) a
 * downstream SIEM/alerting tool is expected to produce for that scenario's underlying event —
 * this is what an operator fills in once they've mapped AgentShield's SIEM export fields to their
 * own tool's alert rules. Scoped to describing expectations for *external* tools; AgentShield's
 * own detections are already validated in-process by {@code AttackSimulatorService} (Phase 2), not
 * by this manifest.
 */
public record ExpectedDetectionsManifest(Map<String, List<String>> expectedAlertNamesByScenario) {

    /**
     * A reasonable starting point an operator can extend/replace — one plausible alert name per
     * scenario, matching the naming an operator might reasonably give an equivalent rule in their
     * own SIEM. Not a claim that any real SIEM produces exactly these names.
     */
    public static ExpectedDetectionsManifest defaultManifest() {
        return new ExpectedDetectionsManifest(Map.ofEntries(
                Map.entry("scenario-1", List.of("AgentShield Tool Schema Drift")),
                Map.entry("scenario-2", List.of("AgentShield Production Destructive Action Blocked")),
                Map.entry("scenario-3", List.of("AgentShield Secret Exposure Blocked")),
                Map.entry("scenario-4", List.of("AgentShield Prompt Injection Blocked")),
                Map.entry("scenario-5", List.of("AgentShield External Transfer Approval Required")),
                Map.entry("scenario-6", List.of("AgentShield Tool Misuse Blocked")),
                Map.entry("scenario-7", List.of("AgentShield Disabled Agent Credential Rejected")),
                Map.entry("scenario-10", List.of("AgentShield MCP OAuth Token Rejected")),
                Map.entry("scenario-11", List.of("AgentShield RAG Chunk DLP Block")),
                Map.entry("scenario-12", List.of("AgentShield Code Assessment Blocked"))));
    }

    public static ExpectedDetectionsManifest fromJson(String json, ObjectMapper mapper) throws java.io.IOException {
        Map<String, List<String>> parsed = mapper.readValue(json, new TypeReference<Map<String, List<String>>>() {
        });
        return new ExpectedDetectionsManifest(parsed);
    }
}
