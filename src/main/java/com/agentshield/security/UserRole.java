package com.agentshield.security;

public enum UserRole {
    ADMIN,
    SECURITY_ANALYST,
    TOOL_OWNER,
    APPROVER,
    AUDITOR,
    /** Machine-client role for CI/CLI submission of code-trust scan results — see SecurityConfig. */
    CI_SCANNER
}
