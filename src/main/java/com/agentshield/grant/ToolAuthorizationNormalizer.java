package com.agentshield.grant;

import com.agentshield.tool.Tool;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * A specifically reviewed extraction for one tool (or tool family) that turns its typed invoke
 * input into {@link NormalizedAuthorizationFacts}. Release one ships zero implementations — until
 * a normalizer is added and reviewed for a given tool, that tool simply cannot carry a
 * resource-path or token-scope grant restriction (see {@link NormalizedAuthorizationFacts}).
 * Never implement this by reading {@code InvokeRequest.context} or an admin-configured JSONPath.
 */
public interface ToolAuthorizationNormalizer {

    boolean supports(Tool tool);

    NormalizedAuthorizationFacts extract(Tool tool, JsonNode input);
}
