package com.agentshield.grant;

import java.util.Set;

/**
 * Trusted resource/scope facts for grant matching — never derived from arbitrary agent-supplied
 * {@code InvokeRequest.context} text, display strings, or an unreviewed admin-configured
 * JSONPath. Release one supports no implicit extraction: a tool either has no resource/scope
 * grant restrictions, or a specifically reviewed {@link ToolAuthorizationNormalizer} emits these
 * facts from a documented field of that tool's typed input. Absent (null) fields must be treated
 * as "not established" — never as satisfying a grant restriction that names that dimension.
 */
public record NormalizedAuthorizationFacts(String resourcePath, Set<String> tokenScopes) {

    public static final NormalizedAuthorizationFacts EMPTY = new NormalizedAuthorizationFacts(null, Set.of());

    public NormalizedAuthorizationFacts {
        tokenScopes = tokenScopes == null ? Set.of() : Set.copyOf(tokenScopes);
    }
}
