package com.agentshield.behavior;

import java.time.Instant;

/**
 * Everything {@link BehaviorBaselineRules} needs to decide whether the current gateway request is
 * unusual for this agent, gathered entirely from history that already exists at request time
 * (the current request's own row/decision are included where the counts are "as of now").
 */
public record BaselineInputs(
        boolean firstTimeCombination,
        long totalPriorRequestsForAgent,
        Instant agentFirstRequestAt,
        long requestsInTrailingHour,
        long denialsInDenialWindow,
        long approvalRequiredInFrequencyWindow
) {
}
