package com.agentshield.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class ProductionSafetyChecksTest {

    @Test
    void refusesToStartWithProdAndDemoBothActive() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod", "demo");
        var checks = new ProductionSafetyChecks(env, "a-real-password");

        assertThatThrownBy(checks::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("prod");
    }

    @Test
    void refusesToStartInProdWithDefaultAdminPassword() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        var checks = new ProductionSafetyChecks(env, "changeit");

        assertThatThrownBy(checks::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AGENTSHIELD_ADMIN_PASSWORD");
    }

    @Test
    void startsFineInProdWithARealPassword() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        var checks = new ProductionSafetyChecks(env, "a-real-password");

        assertThatCode(checks::check).doesNotThrowAnyException();
    }

    @Test
    void doesNotEnforceAdminPasswordCheckOutsideProdProfile() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("demo");
        var checks = new ProductionSafetyChecks(env, "changeit");

        assertThatCode(checks::check).doesNotThrowAnyException();
    }
}
