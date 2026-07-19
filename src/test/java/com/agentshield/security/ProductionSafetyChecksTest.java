package com.agentshield.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.mcp.StdioMcpProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class ProductionSafetyChecksTest {

    private static StdioMcpProperties stdioDisabled() {
        return new StdioMcpProperties();
    }

    @Test
    void refusesToStartWithProdAndDemoBothActive() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod", "demo");
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdioDisabled());

        assertThatThrownBy(checks::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("prod");
    }

    @Test
    void refusesToStartInProdWithDefaultAdminPassword() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        var checks = new ProductionSafetyChecks(env, "changeit", stdioDisabled());

        assertThatThrownBy(checks::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AGENTSHIELD_ADMIN_PASSWORD");
    }

    @Test
    void startsFineInProdWithARealPassword() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdioDisabled());

        assertThatCode(checks::check).doesNotThrowAnyException();
    }

    @Test
    void doesNotEnforceAdminPasswordCheckOutsideProdProfile() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("demo");
        var checks = new ProductionSafetyChecks(env, "changeit", stdioDisabled());

        assertThatCode(checks::check).doesNotThrowAnyException();
    }

    @Test
    void refusesToStartInProdWithStdioEnabledAndNoExternalSandboxAcknowledgement() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        StdioMcpProperties stdio = new StdioMcpProperties();
        stdio.setEnabled(true);
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdio);

        assertThatThrownBy(checks::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("external-sandbox-acknowledged");
    }

    @Test
    void startsFineInProdWithStdioEnabledAndExternalSandboxAcknowledged() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        StdioMcpProperties stdio = new StdioMcpProperties();
        stdio.setEnabled(true);
        stdio.setExternalSandboxAcknowledged(true);
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdio);

        assertThatCode(checks::check).doesNotThrowAnyException();
    }

    @Test
    void doesNotEnforceStdioAcknowledgementOutsideProdProfile() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("demo");
        StdioMcpProperties stdio = new StdioMcpProperties();
        stdio.setEnabled(true);
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdio);

        assertThatCode(checks::check).doesNotThrowAnyException();
    }
}
