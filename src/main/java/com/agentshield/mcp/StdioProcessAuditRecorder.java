package com.agentshield.mcp;

import com.agentshield.audit.AuditService;
import com.agentshield.common.AuditSeverity;
import java.util.Map;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Commits stdio process-lifecycle audit events in their own, independent transaction, deliberately
 * separate from {@link StdioMcpProcessManager}. A subprocess spawn/stop/crash is a real OS-level
 * side effect that has already happened by the time it's audited — if the calling business
 * transaction (e.g. {@code McpDiscoveryService.discover()}, itself {@code @Transactional}) later
 * throws and rolls back, that must never silently erase the record that a process actually
 * started.
 *
 * <p>Uses {@link TransactionTemplate} directly (propagation {@code REQUIRES_NEW}) rather than a
 * {@code @Transactional} annotation for two reasons: (1) a private/self-invoked method wouldn't go
 * through Spring's proxy at all, and (2) it lets this class retry on a concurrent-write deadlock
 * (found via this same stdio/SSE work — multiple background process/connection-manager threads
 * auditing independently can hit MariaDB/InnoDB gap-lock contention on
 * {@code AuditService}'s hash-chain row lock, which the storage engine reports as retryable) by
 * opening a genuinely fresh transaction on each attempt — something an {@code @Transactional}
 * annotation can't do once the first attempt has already poisoned that transaction.
 */
@Component
class StdioProcessAuditRecorder {

    private static final int MAX_LOCK_RETRY_ATTEMPTS = 5;

    private final AuditService auditService;
    private final TransactionTemplate transactionTemplate;

    StdioProcessAuditRecorder(AuditService auditService, PlatformTransactionManager transactionManager) {
        this.auditService = auditService;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    void record(String eventType, AuditSeverity severity, String message, Map<String, Object> metadata) {
        PessimisticLockingFailureException lastFailure = null;
        for (int attempt = 1; attempt <= MAX_LOCK_RETRY_ATTEMPTS; attempt++) {
            try {
                transactionTemplate.executeWithoutResult(status -> auditService.record(null, eventType,
                        com.agentshield.common.ActorType.SYSTEM, "stdio-mcp", null, null, severity, message, metadata));
                return;
            } catch (PessimisticLockingFailureException e) {
                lastFailure = e;
            }
        }
        throw lastFailure;
    }
}
