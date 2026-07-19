package com.agentshield.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.TokenHasher;
import com.agentshield.common.ValidationException;
import com.agentshield.gateway.GatewayDtos;
import com.agentshield.mcp.McpConsentDtos.CreateConsentRequest;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.mcp.McpDtos.StdioStatusResponse;
import com.agentshield.security.AppUser;
import com.agentshield.security.AppUserRepository;
import com.agentshield.security.UserRole;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.support.TestStdioMcpServerMain;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Path;
import java.security.CodeSource;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * design-stdio-sse-mcp-transport-and-sandboxing.md §12. Exercises the sandboxed stdio subprocess
 * lifecycle against a real spawned JVM (com.agentshield.support.TestStdioMcpServerMain) rather
 * than mocking ProcessBuilder — the whole point of these scenarios is proving the actual OS-level
 * behavior (env isolation, output-size abort, timeout kill, crash/respawn), which only a real
 * subprocess can prove.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "agentshield.stdio.enabled=true",
        "agentshield.stdio.allowed-commands=java,java.exe",
        "agentshield.stdio.call-timeout-seconds=3",
        "agentshield.stdio.max-output-bytes=8192",
        "agentshield.stdio.max-concurrent-processes=10",
        "agentshield.stdio.idle-timeout-minutes=60"
})
class StdioMcpIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private McpDiscoveryService discoveryService;
    @Autowired
    private McpConsentService consentService;
    @Autowired
    private McpToolInvoker toolInvoker;
    @Autowired
    private StdioMcpProcessManager processManager;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private AppUserRepository appUserRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    private TestRestTemplate securityAnalystClient() {
        String username = "stdio-security-analyst-" + System.nanoTime();
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode("test-only"));
        user.setEnabled(true);
        user.setRoles(Set.of(UserRole.SECURITY_ANALYST));
        appUserRepository.save(user);
        return new TestRestTemplate(username, "test-only");
    }

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

    private static String argsFor(String mode) {
        return "-cp " + testClassesDir() + " com.agentshield.support.TestStdioMcpServerMain " + mode;
    }

    private McpServer registerStdioServer(String mode, String stdioEnvAllowlist) {
        return discoveryService.register(new RegisterMcpServerRequest(
                "stdio-test-" + mode + "-" + System.nanoTime(), McpTransportType.STDIO, null,
                javaExecutablePath(), argsFor(mode), stdioEnvAllowlist, "owner", "DEV", "mcp"));
    }

    private record Fixture(Agent agent, String plaintextToken) {
    }

    private Fixture createAgentWithCredential(String toolGroup) {
        String plaintextToken = "stdio-test-token-" + System.nanoTime();
        Agent agent = new Agent();
        agent.setName("stdio-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups(toolGroup);
        agent = agentRepository.save(agent);

        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);
        return new Fixture(agent, plaintextToken);
    }

    private GatewayDtos.InvokeResponse invoke(Fixture fixture, Tool tool) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "echo");
        body.put("actionCategory", ActionCategory.READ.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("message", "hi"));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + fixture.plaintextToken());
        return new TestRestTemplate().exchange("http://localhost:" + port + "/api/gateway/invoke",
                HttpMethod.POST, new HttpEntity<>(body, headers), GatewayDtos.InvokeResponse.class).getBody();
    }

    private Tool approvedEchoTool(McpServer server) {
        discoveryService.discover(server.getId());
        Tool tool = toolRepository.findByName(server.getName() + ":echo").orElseThrow();
        tool.setApprovedHash(tool.getCurrentHash());
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        toolRepository.saveAndFlush(tool);
        return tool;
    }

    @Test
    void happyPathDiscoversAndInvokesAnEchoToolThroughTheGateway() {
        McpServer server = registerStdioServer("echo", null);
        Tool tool = approvedEchoTool(server);

        Fixture fixture = createAgentWithCredential("mcp");
        consentService.create(new CreateConsentRequest(fixture.agent().getId(), server.getId(), null, null, null),
                "security-analyst-1");

        var response = invoke(fixture, tool);
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.ALLOW);
    }

    @Test
    void commandNotAllowlistedIsRejectedAtRegistration() {
        var request = new RegisterMcpServerRequest("stdio-bad-command-" + System.nanoTime(), McpTransportType.STDIO,
                null, "python3", "-c pass", null, "owner", "DEV", "mcp");

        assertThatThrownBy(() -> discoveryService.register(request))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("not in the agentshield.stdio.allowed-commands allowlist");
    }

    @Test
    void missingRequiredEnvVarFailsDiscoveryClosed() {
        McpServer server = registerStdioServer("echo", "STDIO_TEST_DEFINITELY_UNSET_VAR_XYZ");

        assertThatThrownBy(() -> discoveryService.discover(server.getId()))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("STDIO_TEST_DEFINITELY_UNSET_VAR_XYZ");
    }

    /**
     * On Windows, the JDK's own ProcessBuilder implementation unconditionally injects SystemRoot
     * into a spawned child's environment regardless of an explicit clear() — confirmed by direct
     * experiment (design-stdio-sse-mcp-transport-and-sandboxing.md §11's correction). It is not
     * secret (always "C:\WINDOWS" or equivalent) and AgentShield's own code cannot suppress it;
     * on Linux (the production target) a cleared environment is genuinely empty. This accounts
     * for that one JDK-level, platform-specific, non-secret exception rather than asserting a
     * false "always exactly zero" claim on every OS.
     */
    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    @Test
    void environmentIsEmptyByDefaultAndOnlyExplicitlyAllowlistedNamesAreCopied() {
        int unavoidablePlatformEntries = isWindows() ? 1 : 0;

        // Empty allowlist: the child sees nothing from AgentShield's own environment (beyond the
        // one unavoidable JDK-on-Windows entry, if any).
        McpServer emptyAllowlistServer = registerStdioServer("dump-env", null);
        JsonNode emptyEnv = dumpChildEnvironment(emptyAllowlistServer);
        assertThat(emptyEnv.size()).isEqualTo(unavoidablePlatformEntries);
        assertThat(emptyEnv.has("PATH")).isFalse();

        // Explicit allowlist of exactly one name: only that name (and its real value) is visible.
        McpServer pathAllowlistServer = registerStdioServer("dump-env", "PATH");
        JsonNode pathEnv = dumpChildEnvironment(pathAllowlistServer);
        assertThat(pathEnv.size()).isEqualTo(unavoidablePlatformEntries + 1);
        assertThat(pathEnv.has("PATH")).isTrue();
        assertThat(pathEnv.get("PATH").asText()).isEqualTo(System.getenv("PATH"));
    }

    private JsonNode dumpChildEnvironment(McpServer server) {
        var result = toolInvoker.invoke(server.getId(), "anything", objectMapper.createObjectNode());
        assertThat(result.success()).as(result.errorMessage()).isTrue();
        return result.parsedBody();
    }

    @Test
    void outputSizeLimitFailsClosedAndKillsTheProcess() {
        McpServer server = registerStdioServer("oversized-output", null);

        var result = toolInvoker.invoke(server.getId(), "anything", objectMapper.createObjectNode());

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessage()).containsIgnoringCase("size");
        assertThat(processManager.status(server.getId()).running()).isFalse();
    }

    @Test
    void callTimeoutFailsClosedAndKillsTheProcess() {
        McpServer server = registerStdioServer("hang", null);

        var result = toolInvoker.invoke(server.getId(), "anything", objectMapper.createObjectNode());

        assertThat(result.success()).isFalse();
        assertThat(result.errorMessage()).containsIgnoringCase("timed out");
        assertThat(processManager.status(server.getId()).running()).isFalse();
    }

    @Test
    void crashedProcessIsDetectedAndTransparentlyRespawned() throws InterruptedException {
        McpServer server = registerStdioServer("crash", null);

        var first = toolInvoker.invoke(server.getId(), "anything", objectMapper.createObjectNode());
        assertThat(first.success()).isTrue();

        Thread.sleep(500); // let the crashed process actually exit before the next call observes it

        var second = toolInvoker.invoke(server.getId(), "anything", objectMapper.createObjectNode());
        assertThat(second.success()).isTrue();
    }

    @Test
    void manualStartStatusAndStopWorkViaTheAdminApi() {
        McpServer server = registerStdioServer("echo", null);

        var startResponse = admin.postForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/stdio/start", null,
                StdioStatusResponse.class);
        assertThat(startResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(startResponse.getBody().running()).isTrue();
        assertThat(startResponse.getBody().pid()).isNotNull();

        var statusResponse = securityAnalystClient().getForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/stdio/status",
                StdioStatusResponse.class);
        assertThat(statusResponse.getBody().running()).isTrue();

        var stopResponse = admin.postForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/stdio/stop", null,
                StdioStatusResponse.class);
        assertThat(stopResponse.getBody().running()).isFalse();
    }

    @Test
    void nonAdminCannotStartOrStopAStdioProcess() {
        McpServer server = registerStdioServer("echo", null);
        TestRestTemplate securityAnalyst = securityAnalystClient();

        var startAttempt = securityAnalyst.postForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/stdio/start", null,
                String.class);
        assertThat(startAttempt.getStatusCode()).isNotEqualTo(HttpStatus.OK);

        var stopAttempt = securityAnalyst.postForEntity(
                "http://localhost:" + port + "/api/mcp-servers/" + server.getId() + "/stdio/stop", null,
                String.class);
        assertThat(stopAttempt.getStatusCode()).isNotEqualTo(HttpStatus.OK);
    }

    @Test
    void consentStillGatesAStdioBackedToolInvocation() {
        McpServer server = registerStdioServer("echo", null);
        Tool tool = approvedEchoTool(server);

        Fixture fixture = createAgentWithCredential("mcp");
        // Deliberately no McpConsent grant.

        var response = invoke(fixture, tool);
        assertThat(response.decision()).isEqualTo(PolicyDecisionType.DENY);
    }
}
