package com.agentshield.dlp;

/** Where in the request/response lifecycle a piece of content was scanned. */
public enum ContentStage {
    INBOUND_PROMPT,
    TOOL_ARGUMENT,
    TOOL_RESULT,
    RAG_CHUNK
}
