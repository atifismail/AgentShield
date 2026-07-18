package com.agentshield.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
            RequestSizeLimitFilter requestSizeLimitFilter) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/css/**", "/js/**", "/vendor/**", "/login").permitAll()
                .requestMatchers("/actuator/health/**", "/actuator/prometheus", "/actuator/info").permitAll()
                .requestMatchers("/api/gateway/**").permitAll()
                .requestMatchers("/demo/**").permitAll()
                .requestMatchers("/api/agents/**").hasRole("ADMIN")
                .requestMatchers("/api/tools/*/approve", "/api/tools/*/reject").hasAnyRole("ADMIN", "TOOL_OWNER", "SECURITY_ANALYST")
                .requestMatchers("/api/policies/**").hasAnyRole("ADMIN", "SECURITY_ANALYST")
                .requestMatchers("/api/approvals/*/approve", "/api/approvals/*/reject").hasAnyRole("ADMIN", "APPROVER")
                .anyRequest().authenticated());

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
