package com.agentshield.security;

import com.agentshield.mcp.StdioMcpProperties;
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
    private final StdioMcpProperties stdioMcpProperties;

    public ProductionSafetyChecks(Environment environment,
            @Value("${agentshield.security.default-admin-password}") String adminPassword,
            StdioMcpProperties stdioMcpProperties) {
        this.environment = environment;
        this.adminPassword = adminPassword;
        this.stdioMcpProperties = stdioMcpProperties;
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
        if (prod && stdioMcpProperties.isEnabled() && !stdioMcpProperties.isExternalSandboxAcknowledged()) {
            throw new IllegalStateException(
                    "Refusing to start: agentshield.stdio.enabled=true with the \"prod\" profile active, but "
                            + "agentshield.stdio.external-sandbox-acknowledged is not set to true. Stdio MCP servers "
                            + "run as local subprocesses that AgentShield cannot fully sandbox on its own (no "
                            + "per-process network egress control, no per-process memory/CPU limit, no filesystem "
                            + "confinement beyond working-directory placement — see "
                            + "design-stdio-sse-mcp-transport-and-sandboxing.md §5.4/§10). Before enabling "
                            + "stdio in production, ensure subprocess isolation is enforced externally (e.g. a "
                            + "Kubernetes NetworkPolicy restricting egress, a seccomp/AppArmor profile, and pod "
                            + "resource limits — see §14), then set "
                            + "agentshield.stdio.external-sandbox-acknowledged=true to confirm this has been done.");
        }
    }
}
