package com.agentshield.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.common.ValidationException;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockMcpServerController;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpDiscoveryServiceTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private ToolRepository toolRepository;

    @BeforeEach
    void resetMockServer() {
        MockMcpServerController.echoToolDescription.set("Echoes its input");
        MockMcpServerController.includeSecondTool.set(true);
    }

    private McpServer registerServer(String name) {
        return discoveryService.register(new RegisterMcpServerRequest(name, McpTransportType.HTTP,
                "http://localhost:" + port + "/demo/mock-mcp-server", null, null, null, "owner", "DEV", "mcp"));
    }

    @Test
    void discoveryCreatesAToolPerDiscoveredMcpTool() {
        McpServer server = registerServer("mcp-server-" + System.nanoTime());

        var result = discoveryService.discover(server.getId());

        assertThat(result.discoveredOrUpdated()).hasSize(2);
        Tool echoTool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();
        assertThat(echoTool.isMcpBacked()).isTrue();
        assertThat(echoTool.getMcpServerId()).isEqualTo(server.getId());
        assertThat(echoTool.getMcpToolName()).isEqualTo("echo");
        assertThat(echoTool.getApprovalStatus()).isEqualTo(ToolApprovalStatus.PENDING);
    }

    @Test
    void rediscoveryAfterDescriptionChangeMarksToolDrifted() {
        McpServer server = registerServer("mcp-server-" + System.nanoTime());
        discoveryService.discover(server.getId());
        Tool echoTool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();

        // Approving is what makes drift detectable — an already-PENDING tool merely gets a new
        // pending version, it can't "drift" from an approved baseline that doesn't exist yet.
        echoTool.setApprovedHash(echoTool.getCurrentHash());
        echoTool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        toolRepository.saveAndFlush(echoTool);

        MockMcpServerController.echoToolDescription.set("Echoes its input, but rewritten by an attacker");
        discoveryService.discover(server.getId());

        Tool afterRediscovery = toolRepository.findByName(server.getName() + ":echo").orElseThrow();
        assertThat(afterRediscovery.getApprovalStatus()).isEqualTo(ToolApprovalStatus.DRIFTED);
    }

    @Test
    void rediscoveryMarksRemovedToolsRejected() {
        McpServer server = registerServer("mcp-server-" + System.nanoTime());
        discoveryService.discover(server.getId());
        assertThat(toolRepository.findByName(server.getName() + ":second-tool")).isPresent();

        MockMcpServerController.includeSecondTool.set(false);
        var result = discoveryService.discover(server.getId());

        assertThat(result.removed()).hasSize(1);
        Tool secondTool = toolRepository.findByName(server.getName() + ":second-tool").orElseThrow();
        assertThat(secondTool.getApprovalStatus()).isEqualTo(ToolApprovalStatus.REJECTED);
    }

    @Test
    void discoveryAgainstANonMcpEndpointFailsClearlyInsteadOfReportingZeroTools() {
        McpServer server = discoveryService.register(new RegisterMcpServerRequest("mcp-server-" + System.nanoTime(),
                McpTransportType.HTTP, "http://localhost:" + port + "/demo/tools/git", null, null, null, "owner",
                "DEV", "mcp"));

        // /demo/tools/git responds with plain JSON, not a JSON-RPC envelope — must not be
        // silently treated as "an MCP server with zero tools."
        assertThatThrownBy(() -> discoveryService.discover(server.getId()))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("not a valid JSON-RPC response");
    }
}
