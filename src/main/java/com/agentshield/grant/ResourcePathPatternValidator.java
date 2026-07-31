package com.agentshield.grant;

import java.util.regex.Pattern;

/**
 * A deliberately small pattern grammar for {@code AgentToolGrant.resourcePathPattern}
 * (agentshield_policy_evidence_execution_plan_2026-07-30.md work package 2): anchored path
 * segments, {@code *} allowed only inside a segment (never across a {@code /}). Rejects
 * traversal, backslashes, URL schemes, control characters, {@code **}, and regex metacharacters —
 * this is a glob, not a regex, and must never be compiled as one directly from operator input.
 */
public final class ResourcePathPatternValidator {

    private static final int MAX_LENGTH = 512;
    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\x00-\\x1F\\x7F]");
    private static final Pattern REGEX_METACHARACTERS = Pattern.compile("[\\[\\]()+?{}^$|\\\\]");

    private ResourcePathPatternValidator() {
    }

    public record ValidationResult(boolean allowed, String reason) {
        public static ValidationResult allow() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult deny(String reason) {
            return new ValidationResult(false, reason);
        }
    }

    public static ValidationResult validate(String pattern) {
        if (pattern == null || pattern.isBlank()) {
            return ValidationResult.deny("resource path pattern must not be blank");
        }
        if (pattern.length() > MAX_LENGTH) {
            return ValidationResult.deny("resource path pattern exceeds the maximum length of " + MAX_LENGTH);
        }
        if (!pattern.startsWith("/")) {
            return ValidationResult.deny("resource path pattern must be anchored (start with '/')");
        }
        if (pattern.contains("..")) {
            return ValidationResult.deny("resource path pattern must not contain '..'");
        }
        if (pattern.contains("\\")) {
            return ValidationResult.deny("resource path pattern must not contain a backslash");
        }
        if (pattern.contains(":")) {
            return ValidationResult.deny("resource path pattern must not contain a URL scheme");
        }
        if (pattern.contains("**")) {
            return ValidationResult.deny("resource path pattern must not contain '**'");
        }
        if (CONTROL_CHARS.matcher(pattern).find()) {
            return ValidationResult.deny("resource path pattern must not contain control characters");
        }
        if (REGEX_METACHARACTERS.matcher(pattern).find()) {
            return ValidationResult.deny("resource path pattern must not contain regex syntax");
        }
        return ValidationResult.allow();
    }

    /** Only call after {@link #validate} has allowed the pattern. */
    public static boolean matches(String pattern, String resourcePath) {
        if (resourcePath == null) {
            return false;
        }
        StringBuilder regex = new StringBuilder("^");
        for (char c : pattern.toCharArray()) {
            if (c == '*') {
                regex.append("[^/]*");
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        regex.append("$");
        return Pattern.compile(regex.toString()).matcher(resourcePath).matches();
    }
}
