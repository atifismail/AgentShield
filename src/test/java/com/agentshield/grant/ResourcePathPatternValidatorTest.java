package com.agentshield.grant;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ResourcePathPatternValidatorTest {

    @Test
    void anchoredPatternWithWildcardSegmentIsAllowed() {
        assertThat(ResourcePathPatternValidator.validate("/repos/*/pulls").allowed()).isTrue();
    }

    @Test
    void patternNotStartingWithSlashIsRejected() {
        var result = ResourcePathPatternValidator.validate("repos/*/pulls");
        assertThat(result.allowed()).isFalse();
        assertThat(result.reason()).contains("anchored");
    }

    @Test
    void patternContainingDotDotIsRejected() {
        assertThat(ResourcePathPatternValidator.validate("/repos/../secrets").allowed()).isFalse();
    }

    @Test
    void patternContainingBackslashIsRejected() {
        assertThat(ResourcePathPatternValidator.validate("/repos\\admin").allowed()).isFalse();
    }

    @Test
    void patternContainingUrlSchemeIsRejected() {
        assertThat(ResourcePathPatternValidator.validate("/http://evil.example.com").allowed()).isFalse();
    }

    @Test
    void patternContainingDoubleStarIsRejected() {
        assertThat(ResourcePathPatternValidator.validate("/repos/**").allowed()).isFalse();
    }

    @Test
    void patternContainingControlCharactersIsRejected() {
        assertThat(ResourcePathPatternValidator.validate("/repos/admin").allowed()).isFalse();
    }

    @Test
    void patternContainingRegexSyntaxIsRejected() {
        assertThat(ResourcePathPatternValidator.validate("/repos/(admin|owner)").allowed()).isFalse();
        assertThat(ResourcePathPatternValidator.validate("/repos/[a-z]+").allowed()).isFalse();
    }

    @Test
    void patternExceedingMaxLengthIsRejected() {
        String tooLong = "/" + "a".repeat(600);
        assertThat(ResourcePathPatternValidator.validate(tooLong).allowed()).isFalse();
    }

    @Test
    void blankPatternIsRejected() {
        assertThat(ResourcePathPatternValidator.validate("").allowed()).isFalse();
        assertThat(ResourcePathPatternValidator.validate(null).allowed()).isFalse();
    }

    @Test
    void wildcardMatchesOnlyWithinASegmentNeverAcrossASlash() {
        assertThat(ResourcePathPatternValidator.matches("/repos/*/pulls", "/repos/agentshield/pulls")).isTrue();
        assertThat(ResourcePathPatternValidator.matches("/repos/*/pulls", "/repos/agentshield/nested/pulls")).isFalse();
    }

    @Test
    void exactPatternMatchesOnlyTheExactPath() {
        assertThat(ResourcePathPatternValidator.matches("/repos/agentshield", "/repos/agentshield")).isTrue();
        assertThat(ResourcePathPatternValidator.matches("/repos/agentshield", "/repos/other")).isFalse();
    }

    @Test
    void nullResourcePathNeverMatchesAnyPattern() {
        assertThat(ResourcePathPatternValidator.matches("/repos/*", null)).isFalse();
    }
}
