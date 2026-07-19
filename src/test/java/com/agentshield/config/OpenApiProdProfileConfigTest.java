package com.agentshield.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * improvement_plan.md (2026-07-19 review), P1 "OpenAPI Production-Disabled Behavior Needs A
 * Direct Test": automates what was previously only checked by hand against a live container.
 * Loads just {@code application.yml}/{@code application-prod.yml} through Spring Boot's normal
 * config-loading machinery — via an empty throwaway {@code @Configuration}, not
 * {@code AgentShieldApplication} — so this doesn't need a datasource, JPA, or
 * {@code ProductionSafetyChecks} satisfied; it tests exactly the property resolution that
 * governs whether springdoc registers its controllers at all.
 */
class OpenApiProdProfileConfigTest {

    @Configuration
    static class EmptyConfig {
    }

    private ConfigurableApplicationContext context(String... profilesAndProps) {
        var builder = new SpringApplicationBuilder(EmptyConfig.class).web(WebApplicationType.NONE);
        for (String p : profilesAndProps) {
            if (p.startsWith("profile:")) {
                builder.profiles(p.substring("profile:".length()));
            } else {
                builder.properties(p);
            }
        }
        return builder.run();
    }

    @Test
    void apiDocsAndSwaggerUiAreDisabledByDefaultInProdProfile() {
        try (var ctx = context("profile:prod")) {
            Environment env = ctx.getEnvironment();
            assertThat(env.getProperty("springdoc.api-docs.enabled", Boolean.class)).isFalse();
            assertThat(env.getProperty("springdoc.swagger-ui.enabled", Boolean.class)).isFalse();
        }
    }

    @Test
    void apiDocsCanBeExplicitlyReEnabledInProdViaEnvVar() {
        try (var ctx = context("profile:prod", "AGENTSHIELD_ENABLE_API_DOCS=true")) {
            Environment env = ctx.getEnvironment();
            assertThat(env.getProperty("springdoc.api-docs.enabled", Boolean.class)).isTrue();
            assertThat(env.getProperty("springdoc.swagger-ui.enabled", Boolean.class)).isTrue();
        }
    }

    @Test
    void apiDocsRemainEnabledByDefaultOutsideProdProfile() {
        try (var ctx = context()) {
            Environment env = ctx.getEnvironment();
            assertThat(env.getProperty("springdoc.api-docs.enabled", Boolean.class)).isTrue();
            assertThat(env.getProperty("springdoc.swagger-ui.enabled", Boolean.class)).isTrue();
        }
    }
}
