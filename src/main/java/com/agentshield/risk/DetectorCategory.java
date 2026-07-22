package com.agentshield.risk;

/** What kind of thing a detector match represents, independent of which detector found it. */
public enum DetectorCategory {
    CREDENTIAL,
    PRIVATE_KEY,
    TOKEN,
    DB_CONNECTION_STRING,
    PROMPT_OVERRIDE,
    TOOL_REDIRECTION,
    HIDDEN_INSTRUCTION,
    EMAIL,
    PHONE,
    NATIONAL_ID,
    FINANCIAL_ACCOUNT,
    CUSTOM_PATTERN
}
