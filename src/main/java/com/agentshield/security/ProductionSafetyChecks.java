package com.agentshield.security;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

/**
 * Refuses to start rather than come up insecure (improvement_plan.md #10). Runs at
 * {@code @PostConstruct} time — during context refresh, before the embedded web server starts
 * listening — so a misconfigured production deployment fails immediately instead of briefly
 * accepting traffic first.
 */
@Component
public class ProductionSafetyChecks {

    private static final String INSECURE_DEFAULT_PASSWORD = "changeit";

    private final Environment environment;
    private final String adminPassword;

    public ProductionSafetyChecks(Environment environment,
            @Value("${agentshield.security.default-admin-password}") String adminPassword) {
        this.environment = environment;
        this.adminPassword = adminPassword;
    }

    @PostConstruct
    public void check() {
        boolean prod = environment.acceptsProfiles(Profiles.of("prod"));
        boolean demo = environment.acceptsProfiles(Profiles.of("demo"));

        if (prod && demo) {
            throw new IllegalStateException(
                    "Refusing to start: the \"prod\" and \"demo\" Spring profiles are both active. "
                            + "The demo mock tools and seed data must never be enabled in production.");
        }
        if (prod && INSECURE_DEFAULT_PASSWORD.equals(adminPassword)) {
            throw new IllegalStateException(
                    "Refusing to start with the \"prod\" profile active and no AGENTSHIELD_ADMIN_PASSWORD set "
                            + "(or it's still the insecure default \"changeit\"). Set a real admin password before "
                            + "starting a production deployment.");
        }
    }
}
