package com.agentshield.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.mcp.McpConsentDtos.CreateConsentRequest;
import com.agentshield.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

/**
 * Regression test for a real production bug: the page rendered raw {@link McpConsent} entities
 * (agent/mcpServer as relation objects), but the template was written against the flattened
 * {@link McpConsentDtos.ConsentResponse} shape (agentName/mcpServerName). With at least one
 * consent row present, Thymeleaf failed evaluating "c.agentName" mid-stream -- after the 200
 * status and part of the body had already been flushed, so the browser got a truncated response
 * (net::ERR_INCOMPLETE_CHUNKED_ENCODING) instead of a clean error page. Every other test that
 * touched this page happened to run against an empty consents list, where the broken expression
 * inside the th:each loop body never executes -- this test is the one with a non-empty list.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpServersPageIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private McpServerRepository mcpServerRepository;
    @Autowired
    private McpConsentService consentService;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    @Test
    void pageRendersConsentRowWithFlattenedAgentAndServerNames() {
        Agent agent = new Agent();
        agent.setName("it-mcp-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent = agentRepository.save(agent);

        McpServer server = new McpServer();
        server.setName("it-mcp-server-" + System.nanoTime());
        server.setTransportType(McpTransportType.HTTP);
        server.setEndpointUrl("https://example.invalid/mcp");
        server = mcpServerRepository.save(server);

        consentService.create(new CreateConsentRequest(agent.getId(), server.getId(), null, null, null), "security-analyst");

        var response = admin.getForEntity("http://localhost:" + port + "/mcp-servers", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains(agent.getName());
        assertThat(response.getBody()).contains(server.getName());
    }
}
