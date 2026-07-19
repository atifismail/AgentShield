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
 * Same independent-transaction-plus-deadlock-retry pattern as {@link StdioProcessAuditRecorder},
 * for the same reasons: an SSE connection open/close/failure is a real side effect that has
 * already happened by the time it's audited, and must survive both a later rollback in the
 * calling business transaction and MariaDB/InnoDB gap-lock contention from concurrent background
 * connection-manager threads auditing independently.
 */
@Component
class McpSseAuditRecorder {

    private static final int MAX_LOCK_RETRY_ATTEMPTS = 5;

    private final AuditService auditService;
    private final TransactionTemplate transactionTemplate;

    McpSseAuditRecorder(AuditService auditService, PlatformTransactionManager transactionManager) {
        this.auditService = auditService;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    void record(String eventType, AuditSeverity severity, String message, Map<String, Object> metadata) {
        PessimisticLockingFailureException lastFailure = null;
        for (int attempt = 1; attempt <= MAX_LOCK_RETRY_ATTEMPTS; attempt++) {
            try {
                transactionTemplate.executeWithoutResult(status -> auditService.record(null, eventType,
                        com.agentshield.common.ActorType.SYSTEM, "mcp-sse", null, null, severity, message, metadata));
                return;
            } catch (PessimisticLockingFailureException e) {
                lastFailure = e;
            }
        }
        throw lastFailure;
    }
}
