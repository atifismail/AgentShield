package com.agentshield.mcp;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Commits stdio process-lifecycle audit events in their own, independent transaction
 * ({@code REQUIRES_NEW}), deliberately separate from {@link StdioMcpProcessManager}. A subprocess
 * spawn/stop/crash is a real OS-level side effect that has already happened by the time it's
 * audited — if the calling business transaction (e.g. {@code McpDiscoveryService.discover()},
 * itself {@code @Transactional}) later throws and rolls back, that must never silently erase the
 * record that a process actually started. A separate Spring-managed bean is required here (not
 * just a private method) because {@code @Transactional} only takes effect through the proxy,
 * which self-invocation within the same class bypasses.
 */
@Component
class StdioProcessAuditRecorder {

    private final AuditService auditService;

    StdioProcessAuditRecorder(AuditService auditService) {
        this.auditService = auditService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void record(String eventType, AuditSeverity severity, String message, Map<String, Object> metadata) {
        auditService.record(null, eventType, ActorType.SYSTEM, "stdio-mcp", null, null, severity, message, metadata);
    }
}
