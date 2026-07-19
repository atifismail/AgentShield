package com.agentshield.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.common.ValidationException;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * design-stdio-sse-mcp-transport-and-sandboxing.md §3/§6: agentshield.stdio.enabled=false is the
 * application default (application.yml). This runs against the default test context (no property
 * overrides), so it shares the cached context most of the suite already uses — no extra startup
 * cost.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class StdioMcpDisabledIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpServerRepository serverRepository;
    @Autowired
    private McpToolInvoker toolInvoker;

    @Test
    void registeringAStdioServerIsRejectedWhileDisabled() {
        var request = new RegisterMcpServerRequest("stdio-disabled-test-" + System.nanoTime(),
                McpTransportType.STDIO, null, "java", "-version", null, "owner", "DEV", "mcp");

        assertThatThrownBy(() -> discoveryService.register(request))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("stdio transport is disabled");
    }

    @Test
    void invokingAPreExistingStdioServerFailsClosedWhileDisabled() {
        // Bypasses register()'s validation on purpose — proves the *runtime call path* also
        // checks the flag, not just registration, in case a server was created before the flag
        // was turned off or via direct DB access.
        McpServer server = new McpServer();
        server.setName("stdio-preexisting-" + System.nanoTime());
        server.setTransportType(McpTransportType.STDIO);
        server.setCommand("java");
        server.setArgs("-version");
        server.setToolGroup("mcp");
        server = serverRepository.save(server);

        var result = toolInvoker.invoke(server.getId(), "anything",
                new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode());

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessage()).containsIgnoringCase("disabled");
    }
}
