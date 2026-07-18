package com.agentshield.common;

/** Input failed a business validation rule (e.g. outbound SSRF policy) — maps to HTTP 400. */
public class ValidationException extends RuntimeException {

    public ValidationException(String message) {
        super(message);
    }
}
