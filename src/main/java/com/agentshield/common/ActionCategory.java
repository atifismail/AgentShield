package com.agentshield.common;

/** Category of an action an agent asks the gateway to perform, used for risk base-scoring. */
public enum ActionCategory {
    READ,
    WRITE,
    DESTRUCTIVE,
    CREDENTIAL_ACCESS,
    EXTERNAL_TRANSFER
}
