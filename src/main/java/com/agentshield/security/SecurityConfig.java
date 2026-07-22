package com.agentshield.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Full RBAC security configuration: form login for the admin UI/API, the gateway's own
 * bearer-token auth for /api/gateway/** (not Spring Security session auth — see
 * {@link com.agentshield.gateway.GatewayService#authenticate}), CSRF for browser-originated
 * state changes, secure headers, and the rate-limit / request-size filters.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, RateLimitFilter rateLimitFilter,
            RequestSizeLimitFilter requestSizeLimitFilter, Environment environment) throws Exception {
        // /demo/** (the bundled mock tools) is only ever reachable when the "demo" profile is
        // active — the controllers themselves are @Profile("demo")-gated too (so they 404 when
        // the profile is off), but the permitAll rule is also kept out of non-demo deployments
        // entirely rather than relying on the controllers' absence alone (improvement_plan.md #5).
        boolean demoProfileActive = environment.acceptsProfiles(Profiles.of("demo"));

        http.authorizeHttpRequests(auth -> {
            auth.requestMatchers("/css/**", "/js/**", "/vendor/**", "/login").permitAll();
            auth.requestMatchers(EndpointRequest.to("health", "info", "prometheus")).permitAll();
            // No-op when springdoc.api-docs.enabled/swagger-ui.enabled are false (prod default,
            // improvement_plan.md #13) — springdoc doesn't register the underlying controllers at
            // all in that case, so an anonymous request gets this app's usual unmapped-path
            // response (401, not 404 — Spring Security re-secures the internal /error forward,
            // same as any other nonexistent path here) rather than the docs themselves.
            auth.requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll();
            auth.requestMatchers("/api/gateway/**").permitAll();
            if (demoProfileActive) {
                auth.requestMatchers("/demo/**").permitAll();
            }
            auth.requestMatchers("/api/agents/**").hasRole("ADMIN");
            auth.requestMatchers("/api/tools/*/approve", "/api/tools/*/reject").hasAnyRole("ADMIN", "TOOL_OWNER", "SECURITY_ANALYST");
            auth.requestMatchers("/api/tools/*/provenance/**").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.requestMatchers("/api/policies/**", "/api/policy-overrides/**").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.requestMatchers("/api/dlp/profiles/**").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            // CI_SCANNER is a machine-client role for scripts/agentshield-code-scan.sh and CI
            // pipelines submitting scan results via Basic Auth — deliberately not the gateway's
            // bearer-token path (that stays scoped to /api/gateway/** only, see class javadoc).
            // The approve/reject matcher is intentionally declared before the broader
            // assessments/** one below — Spring Security uses the first matcher that matches a
            // request, so CI_SCANNER must never reach the review endpoints.
            auth.requestMatchers("/api/codetrust/assessments/*/approve", "/api/codetrust/assessments/*/reject")
                    .hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.requestMatchers("/api/codetrust/assessments", "/api/codetrust/assessments/**")
                    .hasAnyRole("ADMIN", "SECURITY_ANALYST", "CI_SCANNER");
            auth.requestMatchers("/api/governance/**").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.requestMatchers("/api/siem/**").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.requestMatchers("/api/approvals/*/approve", "/api/approvals/*/reject").hasAnyRole("ADMIN", "APPROVER");
            auth.requestMatchers("/api/incidents/*/status").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.requestMatchers("/api/mcp-servers/*/auth").hasRole("ADMIN");
            auth.requestMatchers("/api/mcp-servers/*/stdio/start", "/api/mcp-servers/*/stdio/stop").hasRole("ADMIN");
            auth.requestMatchers("/api/mcp-servers/*/stdio/status").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.requestMatchers("/api/mcp-servers/*/sse/start", "/api/mcp-servers/*/sse/stop").hasRole("ADMIN");
            auth.requestMatchers("/api/mcp-servers/*/sse/status").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.requestMatchers("/api/mcp-consents/**").hasAnyRole("ADMIN", "SECURITY_ANALYST");
            auth.anyRequest().authenticated();
        });

        http.formLogin(form -> form
                .loginPage("/login")
                .permitAll());

        // Enabled alongside form login for scripted/API-tool access (e.g. curl, CI smoke tests);
        // the browser UI itself always uses the session established by form login.
        http.httpBasic(basic -> {
        });

        http.logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll());

        // CSRF protects cookie/session-authenticated (browser) requests from being forged by
        // another site. It does not apply to Basic-Auth-authenticated requests: those require
        // the caller to explicitly know and send credentials on every request (no ambient
        // browser-attached credential for a forged request to ride along on), so a curl/CI/API
        // client authenticating with Basic Auth is exempted — otherwise no stateless client
        // could ever call a state-changing endpoint (CSRF is enforced in the filter chain before
        // Basic Auth even runs, so without this exemption every such call gets a bogus 401).
        http.csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/gateway/**", "/demo/**")
                .ignoringRequestMatchers(request -> {
                    String header = request.getHeader("Authorization");
                    return header != null && header.regionMatches(true, 0, "Basic ", 0, 6);
                }));

        http.headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .contentTypeOptions(withDefaults -> {
                })
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN))
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                + "object-src 'none'; base-uri 'self'; frame-ancestors 'none'")));

        http.addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(requestSizeLimitFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
