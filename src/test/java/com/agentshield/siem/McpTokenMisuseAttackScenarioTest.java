package com.agentshield.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.mcp.McpAuthMode;
import com.agentshield.mcp.McpDiscoveryService;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.mcp.McpDtos.UpdateMcpAuthRequest;
import com.agentshield.mcp.McpOAuthTokenService;
import com.agentshield.mcp.McpServer;
import com.agentshield.mcp.McpTransportType;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.MockOAuthServerController;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * SOC Validation Module (N1) scenario-10: MCP OAuth token misuse (wrong audience) must be
 * rejected, never cached. Deliberately <b>not</b> part of {@link AttackSimulatorService#runAll()}
 * — see that class's javadoc for why this scenario needs the test-only mock OAuth server
 * ({@link MockOAuthServerController}) and can't safely be exposed via the live
 * {@code POST /api/siem/validate} endpoint. This test mirrors
 * {@code McpOAuthTokenServiceTest.rejectsATokenWithTheWrongAudience()}'s exact setup, and records
 * its own {@link DetectionValidationRun} row so scenario-10 still shows up in the coverage/SOC
 * validation dashboards as "last validated".
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpTokenMisuseAttackScenarioTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpOAuthTokenService oauthTokenService;
    @Autowired
    private DetectionValidationRunRepository validationRunRepository;

    @BeforeEach
    @AfterEach
    void resetMockOAuthServer() {
        MockOAuthServerController.reset();
    }

    @Test
    void wrongAudienceTokenIsRejectedAndNeverCached() {
        McpServer server = discoveryService.register(new RegisterMcpServerRequest(
                "attack-simulator-oauth-server-" + System.nanoTime(), McpTransportType.HTTP,
                "http://localhost:" + port + "/demo/mock-mcp-server", null, null, null, "owner", "DEV", "mcp"));
        String issuer = "http://localhost:" + port + "/demo/mock-oauth-server";
        String resource = "http://localhost:" + port + "/demo/mock-mcp-server";
        MockOAuthServerController.issuerOverride.set(issuer);
        // updateAuth returns the updated entity rather than mutating the original in place —
        // must use its return value, not the pre-update `server` reference (which still carries
        // AuthMode.NONE and would make getValidToken fail with "no token endpoint" instead of the
        // intended wrong-audience rejection).
        server = discoveryService.updateAuth(server.getId(),
                new UpdateMcpAuthRequest(McpAuthMode.OAUTH2, issuer, resource, null, "test-client", null, null));
        MockOAuthServerController.audienceOverride.set("https://some-other-resource.example.com");

        var result = oauthTokenService.getValidToken(server);

        boolean passed = !result.success() && result.errorMessage() != null && result.errorMessage().contains("aud");

        DetectionValidationRun run = new DetectionValidationRun();
        run.setScenarioCode("scenario-10");
        run.setDetectionRuleCode("mcp-oauth-token-rejected");
        run.setPassed(passed);
        run.setDetail("success=" + result.success() + " errorMessage=" + result.errorMessage());
        run.setTriggeredBy("attack-simulator");
        validationRunRepository.save(run);

        assertThat(passed).as("scenario-10 (MCP OAuth token misuse): success=%s errorMessage=%s",
                result.success(), result.errorMessage()).isTrue();
    }
}
