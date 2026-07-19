package com.agentshield.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI metadata (improvement_plan.md #13). Served at {@code /v3/api-docs}, browsable at
 * {@code /swagger-ui.html} — both off by default in the {@code prod} profile (see
 * {@code application-prod.yml}).
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI agentShieldOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("AgentShield API")
                        .description("Runtime guardrail gateway for AI agent tool calls: policy enforcement, "
                                + "risk scoring, response scanning, and the admin APIs (agents, tools, approvals, "
                                + "audit, incidents) that operate it.")
                        .version("v1")
                        .license(new License().name("GPL-3.0")))
                .addSecurityItem(new SecurityRequirement().addList("agentBearerToken"))
                .addSecurityItem(new SecurityRequirement().addList("basicAuth"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("agentBearerToken", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .description("Per-agent token, used only by POST /api/gateway/invoke"))
                        .addSecuritySchemes("basicAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("basic")
                                .description("Human operator credentials, used by every other /api/** endpoint")));
    }
}
