package com.agentshield.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.support.AbstractIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuditIntegrityServiceTest extends AbstractIntegrationTest {

    @Autowired
    private AuditService auditService;
    @Autowired
    private AuditEventRepository auditEventRepository;
    @Autowired
    private AuditIntegrityService integrityService;
    @Autowired
    private MeterRegistry meterRegistry;

    @Test
    void freshlyWrittenChainVerifiesAsValid() {
        auditService.record(null, "test.chain.a", ActorType.SYSTEM, "tester", null, null, AuditSeverity.INFO,
                "first event", null);
        auditService.record(null, "test.chain.b", ActorType.SYSTEM, "tester", null, null, AuditSeverity.INFO,
                "second event", null);
        auditService.record(null, "test.chain.c", ActorType.SYSTEM, "tester", null, null, AuditSeverity.INFO,
                "third event", null);

        var result = integrityService.verifyChain();

        assertThat(result.valid()).isTrue();
        assertThat(result.firstBrokenEventId()).isNull();
    }

    @Test
    void eachEventLinksToThePreviousEventsHash() {
        var first = auditService.record(null, "test.chain.link.a", ActorType.SYSTEM, "tester", null, null,
                AuditSeverity.INFO, "first", null);
        var second = auditService.record(null, "test.chain.link.b", ActorType.SYSTEM, "tester", null, null,
                AuditSeverity.INFO, "second", null);

        assertThat(second.getPreviousEventHash()).isEqualTo(first.getEventHash());
        assertThat(second.getEventHash()).isNotEqualTo(first.getEventHash());
    }

    @Test
    void tamperingWithAnEventsMessageBreaksVerification() {
        var event = auditService.record(null, "test.chain.tamper", ActorType.SYSTEM, "tester", null, null,
                AuditSeverity.INFO, "original message", null);
        auditService.record(null, "test.chain.tamper.next", ActorType.SYSTEM, "tester", null, null,
                AuditSeverity.INFO, "next event after the one we'll tamper with", null);

        // Simulate an attacker editing history directly in the database, bypassing AuditService.
        AuditEvent stored = auditEventRepository.findById(event.getId()).orElseThrow();
        stored.setMessage("tampered message — this should never verify");
        auditEventRepository.saveAndFlush(stored);

        try {
            var result = integrityService.verifyChain();

            assertThat(result.valid()).isFalse();
            assertThat(result.firstBrokenEventId()).isEqualTo(event.getId());
        } finally {
            // verifyChain() scans the whole table, and this class's tests share one database
            // (the Testcontainers container is a suite-wide singleton, per AbstractIntegrationTest)
            // — restore the original message so this test's deliberate tampering doesn't
            // permanently break every later chain-verification assertion in this JVM's test run.
            stored.setMessage("original message");
            auditEventRepository.saveAndFlush(stored);
        }
    }

    /** docs/operations.md "Monitoring and alerting": the scheduled check backs a Prometheus gauge. */
    @Test
    void scheduledVerifySetsTheIntegrityGaugeToOneWhenTheChainIsValid() {
        auditService.record(null, "test.chain.scheduled.valid", ActorType.SYSTEM, "tester", null, null,
                AuditSeverity.INFO, "valid chain event", null);

        integrityService.scheduledVerify();

        assertThat(meterRegistry.get("agentshield_audit_integrity_valid").gauge().value()).isEqualTo(1.0);
    }

    @Test
    void scheduledVerifySetsTheIntegrityGaugeToZeroAndAuditsWhenTamperingIsFound() {
        var event = auditService.record(null, "test.chain.scheduled.tamper", ActorType.SYSTEM, "tester", null, null,
                AuditSeverity.INFO, "original message", null);
        auditService.record(null, "test.chain.scheduled.tamper.next", ActorType.SYSTEM, "tester", null, null,
                AuditSeverity.INFO, "next event", null);

        AuditEvent stored = auditEventRepository.findById(event.getId()).orElseThrow();
        stored.setMessage("tampered — scheduled check should catch this");
        auditEventRepository.saveAndFlush(stored);

        try {
            integrityService.scheduledVerify();

            assertThat(meterRegistry.get("agentshield_audit_integrity_valid").gauge().value()).isEqualTo(0.0);
            assertThat(auditEventRepository.findAll().stream()
                    .anyMatch(e -> "audit.integrity_check_failed".equals(e.getEventType())
                            && e.getSeverity() == AuditSeverity.CRITICAL))
                    .isTrue();
        } finally {
            // Same reasoning as tamperingWithAnEventsMessageBreaksVerification: restore the row so
            // this test's deliberate tampering doesn't poison every later verifyChain() call in
            // this JVM's test run — including the scheduledVerify() gauge itself, which every
            // subsequent test in this class (and the real @Scheduled trigger on its next tick)
            // would otherwise see stuck at 0 regardless of what they write.
            stored.setMessage("original message");
            auditEventRepository.saveAndFlush(stored);
            integrityService.scheduledVerify();
        }
    }
}
