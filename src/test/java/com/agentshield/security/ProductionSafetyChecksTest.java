package com.agentshield.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.codetrust.ReceiptSigningKeyProvider;
import com.agentshield.mcp.StdioMcpProperties;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class ProductionSafetyChecksTest {

    private static StdioMcpProperties stdioDisabled() {
        return new StdioMcpProperties();
    }

    /** Ephemeral is fine wherever the test expects to fail/short-circuit on an earlier check. */
    private static ReceiptSigningKeyProvider ephemeralSigningKey() {
        return new ReceiptSigningKeyProvider("", "", "test-key");
    }

    /** A real, non-ephemeral key — required wherever the test expects `check()` to pass cleanly. */
    private static ReceiptSigningKeyProvider configuredSigningKey() {
        try {
            KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
            return new ReceiptSigningKeyProvider(privateKey, publicKey, "test-key");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void refusesToStartWithProdAndDemoBothActive() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod", "demo");
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdioDisabled(), ephemeralSigningKey());

        assertThatThrownBy(checks::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("prod");
    }

    @Test
    void refusesToStartInProdWithDefaultAdminPassword() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        var checks = new ProductionSafetyChecks(env, "changeit", stdioDisabled(), ephemeralSigningKey());

        assertThatThrownBy(checks::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AGENTSHIELD_ADMIN_PASSWORD");
    }

    @Test
    void startsFineInProdWithARealPassword() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdioDisabled(), configuredSigningKey());

        assertThatCode(checks::check).doesNotThrowAnyException();
    }

    @Test
    void doesNotEnforceAdminPasswordCheckOutsideProdProfile() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("demo");
        var checks = new ProductionSafetyChecks(env, "changeit", stdioDisabled(), ephemeralSigningKey());

        assertThatCode(checks::check).doesNotThrowAnyException();
    }

    @Test
    void refusesToStartInProdWithStdioEnabledAndNoExternalSandboxAcknowledgement() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        StdioMcpProperties stdio = new StdioMcpProperties();
        stdio.setEnabled(true);
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdio, ephemeralSigningKey());

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
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdio, configuredSigningKey());

        assertThatCode(checks::check).doesNotThrowAnyException();
    }

    @Test
    void refusesToStartInProdWithAnEphemeralCodeTrustSigningKey() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdioDisabled(), ephemeralSigningKey());

        assertThatThrownBy(checks::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("codetrust.signing-private-key");
    }

    @Test
    void doesNotEnforceStdioAcknowledgementOutsideProdProfile() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("demo");
        StdioMcpProperties stdio = new StdioMcpProperties();
        stdio.setEnabled(true);
        var checks = new ProductionSafetyChecks(env, "a-real-password", stdio, ephemeralSigningKey());

        assertThatCode(checks::check).doesNotThrowAnyException();
    }
}
