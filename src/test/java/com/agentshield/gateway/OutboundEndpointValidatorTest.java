package com.agentshield.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OutboundEndpointValidatorTest {

    private final OutboundPolicyProperties properties = new OutboundPolicyProperties();
    private final OutboundEndpointValidator validator = new OutboundEndpointValidator(properties);

    @Test
    void allowsRelativeDemoPathsByDefault() {
        assertThat(validator.validate("/demo/tools/git").allowed()).isTrue();
    }

    @Test
    void deniesRelativePathsWhenDemoToolsDisabled() {
        properties.setAllowRelativeDemoTools(false);
        var validator = new OutboundEndpointValidator(properties);
        assertThat(validator.validate("/demo/tools/git").allowed()).isFalse();
    }

    @Test
    void deniesCloudMetadataAddress() {
        var result = validator.validate("http://169.254.169.254/latest/meta-data/");
        assertThat(result.allowed()).isFalse();
        assertThat(result.reason()).contains("blocked address range");
    }

    @Test
    void deniesPrivateNetworkAddress() {
        assertThat(validator.validate("http://10.0.0.5/api").allowed()).isFalse();
        assertThat(validator.validate("http://192.168.1.1/api").allowed()).isFalse();
    }

    @Test
    void allowsExplicitlyAllowedHostDespiteBlockedRange() {
        var result = validator.validate("http://localhost:9999/api");
        assertThat(result.allowed()).isTrue();
    }

    @Test
    void allowsOrdinaryPublicHost() {
        assertThat(validator.validate("https://example.com/v1/records").allowed()).isTrue();
    }

    @Test
    void deniesNonHttpScheme() {
        var result = validator.validate("ftp://example.com/file");
        assertThat(result.allowed()).isFalse();
        assertThat(result.reason()).contains("http or https");
    }

    @Test
    void denyAllUnlessAllowedRejectsEverythingNotExplicitlyListed() {
        properties.setDenyAllUnlessAllowed(true);
        var strictValidator = new OutboundEndpointValidator(properties);
        assertThat(strictValidator.validate("https://example.com/v1").allowed()).isFalse();
        assertThat(strictValidator.validate("http://localhost:8080/x").allowed()).isTrue();
    }
}
