package com.agentshield.approval;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.ConflictException;
import com.agentshield.common.TokenHasher;
import com.agentshield.gateway.GatewayDtos;
import com.agentshield.gateway.GatewayToolResponseRepository;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * improvement_plan.md (2026-07-19 review), P1 "Approval Concurrency Needs A Negative Security
 * Test": two threads racing to approve the same pending action must not both execute the tool
 * call — one wins, the other gets a conflict, and exactly one forensic response row is written.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApprovalConcurrencyIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private ApprovalRequestRepository approvalRequestRepository;
    @Autowired
    private ApprovalService approvalService;
    @Autowired
    private GatewayToolResponseRepository toolResponseRepository;
    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void concurrentApprovalsExecuteTheToolCallExactlyOnce() throws Exception {
        String plaintextToken = "test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("it-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("database");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        Tool tool = new Tool();
        tool.setName("it-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup("database");
        tool.setEndpointUrl("http://localhost:" + port + "/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setApprovedHash("h");
        tool.setCurrentHash("h");
        tool = toolRepository.save(tool);

        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "deleteRecords");
        body.put("actionCategory", ActionCategory.WRITE.name());
        body.put("targetEnvironment", "PROD");
        body.set("input", objectMapper.createObjectNode().put("table", "users"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);
        TestRestTemplate rest = new TestRestTemplate();
        var invokeResponse = rest.postForEntity("http://localhost:" + port + "/api/gateway/invoke",
                new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class);
        Long approvalId = invokeResponse.getBody().approvalRequestId();
        assertThat(approvalId).isNotNull();

        int threadCount = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch ready = new CountDownLatch(threadCount);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger succeeded = new AtomicInteger();
        AtomicInteger conflicted = new AtomicInteger();

        List<Callable<Void>> tasks = java.util.stream.IntStream.range(0, threadCount)
                .<Callable<Void>>mapToObj(i -> () -> {
                    ready.countDown();
                    go.await();
                    try {
                        approvalService.approve(approvalId, "security-analyst-" + i);
                        succeeded.incrementAndGet();
                    } catch (ConflictException e) {
                        conflicted.incrementAndGet();
                    }
                    return null;
                })
                .toList();

        List<Future<Void>> futures = tasks.stream().map(pool::submit).toList();
        ready.await(5, TimeUnit.SECONDS);
        go.countDown();
        for (Future<Void> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        assertThat(succeeded.get()).isEqualTo(1);
        assertThat(conflicted.get()).isEqualTo(threadCount - 1);
        assertThat(approvalRequestRepository.findById(approvalId).orElseThrow().getStatus().name()).isEqualTo("APPROVED");

        var gatewayRequestId = approvalRequestRepository.findById(approvalId).orElseThrow().getGatewayRequest().getId();
        assertThat(toolResponseRepository.countByGatewayRequestId(gatewayRequestId)).isEqualTo(1);
    }
}
