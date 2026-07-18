package com.agentshield.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.support.AbstractIntegrationTest;
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

        var result = integrityService.verifyChain();

        assertThat(result.valid()).isFalse();
        assertThat(result.firstBrokenEventId()).isEqualTo(event.getId());
    }
}
