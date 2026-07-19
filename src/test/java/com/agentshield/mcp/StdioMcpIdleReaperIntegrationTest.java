package com.agentshield.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.TestStdioMcpServerMain;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.security.CodeSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * design-stdio-sse-mcp-transport-and-sandboxing.md §4.5: an idle process is stopped by the
 * reaper. Isolated in its own context with idle-timeout-minutes=0 so "idle" is true almost
 * immediately, and calls {@link StdioMcpProcessManager#reapIdleProcesses()} directly rather than
 * waiting for the real @Scheduled(fixedDelayString = "PT1M") trigger — the method is a plain
 * public method, so this is deterministic and doesn't require waiting a real minute.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "agentshield.stdio.enabled=true",
        "agentshield.stdio.allowed-commands=java,java.exe",
        "agentshield.stdio.call-timeout-seconds=5",
        "agentshield.stdio.idle-timeout-minutes=0"
})
class StdioMcpIdleReaperIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpToolInvoker toolInvoker;
    @Autowired
    private StdioMcpProcessManager processManager;
    @Autowired
    private ObjectMapper objectMapper;

    private static String javaExecutablePath() {
        String javaHome = System.getProperty("java.home");
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        return Path.of(javaHome, "bin", windows ? "java.exe" : "java").toString();
    }

    private static String testClassesDir() {
        try {
            CodeSource source = TestStdioMcpServerMain.class.getProtectionDomain().getCodeSource();
            return Path.of(source.getLocation().toURI()).toAbsolutePath().toString();
        } catch (Exception e) {
            throw new IllegalStateException("could not resolve test classes directory", e);
        }
    }

    @Test
    void idleProcessIsStoppedByTheReaperAndRespawnsTransparentlyOnNextUse() throws InterruptedException {
        String args = "-cp " + testClassesDir() + " com.agentshield.support.TestStdioMcpServerMain echo";
        McpServer server = discoveryService.register(new RegisterMcpServerRequest("stdio-idle-test-" + System.nanoTime(),
                McpTransportType.STDIO, null, javaExecutablePath(), args, null, "owner", "DEV", "mcp"));

        var firstCall = toolInvoker.invoke(server.getId(), "anything", objectMapper.createObjectNode());
        assertThat(firstCall.success()).isTrue();
        assertThat(processManager.status(server.getId()).running()).isTrue();

        // idle-timeout-minutes=0 makes "cutoff" effectively "now" — sleep past a clock tick so
        // lastActivityAt is unambiguously before the reaper's cutoff even on coarse-resolution
        // clocks (observed: two Instant.now() calls in quick succession can land on the same
        // millisecond on Windows, making a strict isBefore() comparison a tie).
        Thread.sleep(50);
        processManager.reapIdleProcesses();

        assertThat(processManager.status(server.getId()).running()).isFalse();

        var secondCall = toolInvoker.invoke(server.getId(), "anything", objectMapper.createObjectNode());
        assertThat(secondCall.success()).isTrue();
    }
}
