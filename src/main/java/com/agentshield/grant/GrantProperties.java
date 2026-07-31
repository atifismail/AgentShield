package com.agentshield.grant;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Defaults to {@link GrantTransitionMode#GROUPS_ONLY} so every existing installation (and this
 * project's own regression suite, which seeds agents via the legacy {@code allowedToolGroups}
 * field) keeps behaving exactly as before until an operator explicitly opts in — see
 * docs/policy-guide.md for the migration path. Never flip this default for the bundled demo
 * profile; that would silently break every agent seeded by the demo data without any grants.
 */
@Component
@ConfigurationProperties(prefix = "agentshield.grants")
public class GrantProperties {

    private GrantTransitionMode transitionMode = GrantTransitionMode.GROUPS_ONLY;

    public GrantTransitionMode getTransitionMode() {
        return transitionMode;
    }

    public void setTransitionMode(GrantTransitionMode transitionMode) {
        this.transitionMode = transitionMode;
    }
}
