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
 * design-stdio-sse-mcp-transport-and-sandboxing.md §4.2 step 3 / §12: isolated in its own Spring
 * context (a low agentshield.stdio.max-concurrent-processes would otherwise interfere with every
 * other stdio test class sharing a context).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "agentshield.stdio.enabled=true",
        "agentshield.stdio.allowed-commands=java,java.exe",
        "agentshield.stdio.call-timeout-seconds=5",
        "agentshield.stdio.max-concurrent-processes=1"
})
class StdioMcpProcessLimitIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpToolInvoker toolInvoker;
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

    private McpServer registerEchoServer() {
        String args = "-cp " + testClassesDir() + " com.agentshield.support.TestStdioMcpServerMain echo";
        return discoveryService.register(new RegisterMcpServerRequest("stdio-limit-test-" + System.nanoTime(),
                McpTransportType.STDIO, null, javaExecutablePath(), args, null, "owner", "DEV", "mcp"));
    }

    @Test
    void secondProcessBeyondTheConcurrentLimitFailsClosed() {
        McpServer first = registerEchoServer();
        McpServer second = registerEchoServer();

        var firstResult = toolInvoker.invoke(first.getId(), "anything", objectMapper.createObjectNode());
        assertThat(firstResult.success()).isTrue();

        var secondResult = toolInvoker.invoke(second.getId(), "anything", objectMapper.createObjectNode());
        assertThat(secondResult.success()).isFalse();
        assertThat(secondResult.errorMessage()).containsIgnoringCase("capacity");

        // The first server's process is unaffected by the second's failed spawn attempt.
        var firstAgain = toolInvoker.invoke(first.getId(), "anything", objectMapper.createObjectNode());
        assertThat(firstAgain.success()).isTrue();
    }
}
