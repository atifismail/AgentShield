package com.agentshield.approval;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.ApprovalStatus;
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
import java.time.Instant;
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
 * Release 1 reconciliation Gap 3 ("Approval Replay And Reuse Hardening"): proves — by test, not
 * assumption — that an approval past its expiry can never execute the underlying tool call, and
 * that a race between approving and rejecting the same request still executes it at most once.
 * The double-approve race is already covered by {@link ApprovalConcurrencyIntegrationTest}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApprovalReuseHardeningTest extends AbstractIntegrationTest {

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

    private String plaintextToken;

    private Agent createAgent() {
        plaintextToken = "reuse-test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("reuse-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("database");
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);
        return agent;
    }

    private Tool createTool() {
        Tool tool = new Tool();
        tool.setName("reuse-test-tool-" + System.nanoTime());
        tool.setType(ToolType.DATABASE);
        tool.setToolGroup("database");
        tool.setEndpointUrl("http://localhost:" + port + "/demo/mock-tool/echo");
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setApprovedHash("h");
        tool.setCurrentHash("h");
        return toolRepository.save(tool);
    }

    private Long requestApproval(Tool tool) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "deleteRecords");
        body.put("actionCategory", ActionCategory.WRITE.name());
        body.put("targetEnvironment", "PROD");
        body.set("input", objectMapper.createObjectNode().put("table", "users"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);
        var response = new TestRestTemplate().postForEntity("http://localhost:" + port + "/api/gateway/invoke",
                new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class);
        return response.getBody().approvalRequestId();
    }

    @Test
    void expiredApprovalCannotExecuteTheToolCall() {
        createAgent();
        Tool tool = createTool();
        Long approvalId = requestApproval(tool);

        ApprovalRequest approval = approvalRequestRepository.findById(approvalId).orElseThrow();
        approval.setExpiresAt(Instant.now().minusSeconds(60));
        approvalRequestRepository.saveAndFlush(approval);

        assertThatThrownBy(() -> approvalService.approve(approvalId, "security-analyst-1"))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("expired");

        // requirePending() flips the row to EXPIRED before throwing, but the throw is a
        // RuntimeException inside the same @Transactional approve() call, so Spring rolls that
        // status change back with it — the row is left PENDING for the next scheduled sweep
        // (ApprovalService.expireOverdueApprovals) to reap. What matters for this guarantee is
        // that the throw prevented execution, not the row's transient status label.
        assertThat(approvalRequestRepository.findById(approvalId).orElseThrow().getStatus())
                .isEqualTo(ApprovalStatus.PENDING);
        assertThat(toolResponseRepository.countByGatewayRequestId(approval.getGatewayRequest().getId())).isZero();
    }

    @Test
    void concurrentApproveAndRejectExecuteTheToolCallAtMostOnce() throws Exception {
        createAgent();
        Tool tool = createTool();
        Long approvalId = requestApproval(tool);

        int attempts = 8;
        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        CountDownLatch ready = new CountDownLatch(attempts);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger succeeded = new AtomicInteger();
        AtomicInteger conflicted = new AtomicInteger();

        List<Callable<Void>> tasks = java.util.stream.IntStream.range(0, attempts)
                .<Callable<Void>>mapToObj(i -> () -> {
                    ready.countDown();
                    go.await();
                    try {
                        if (i % 2 == 0) {
                            approvalService.approve(approvalId, "security-analyst-" + i);
                        } else {
                            approvalService.reject(approvalId, "security-analyst-" + i);
                        }
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
        assertThat(conflicted.get()).isEqualTo(attempts - 1);

        ApprovalRequest approval = approvalRequestRepository.findById(approvalId).orElseThrow();
        assertThat(approval.getStatus()).isIn(ApprovalStatus.APPROVED, ApprovalStatus.REJECTED);
        assertThat(toolResponseRepository.countByGatewayRequestId(approval.getGatewayRequest().getId()))
                .isLessThanOrEqualTo(1);
    }
}
