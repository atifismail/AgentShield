package com.agentshield.mcp;

import com.agentshield.common.AuditSeverity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.annotation.PreDestroy;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Owns every live stdio MCP subprocess (design-stdio-sse-mcp-transport-and-sandboxing.md §4). One
 * process per registered STDIO server, spawned lazily on first use, calls serialized per process
 * (v1 scope decision — §4.4, no request pipelining), reaped when idle, respawned transparently on
 * crash. All state here is in-memory only — never persisted (§4.1/§8) — so an AgentShield restart
 * simply loses every managed process, which is expected and safe (they're re-spawned lazily).
 */
@Component
public class StdioMcpProcessManager {

    private final StdioMcpProperties properties;
    private final StdioCommandValidator commandValidator;
    private final StdioProcessAuditRecorder auditRecorder;
    private final ObjectMapper objectMapper;
    private final Map<Long, ManagedProcess> processes = new ConcurrentHashMap<>();
    private final ExecutorService ioExecutor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "stdio-mcp-io");
        t.setDaemon(true);
        return t;
    });
    private final AtomicLong requestIdSeq = new AtomicLong(1);

    public StdioMcpProcessManager(StdioMcpProperties properties, StdioCommandValidator commandValidator,
            StdioProcessAuditRecorder auditRecorder, ObjectMapper objectMapper) {
        this.properties = properties;
        this.commandValidator = commandValidator;
        this.auditRecorder = auditRecorder;
        this.objectMapper = objectMapper;
    }

    public StdioRpcResult call(McpServer server, String method, JsonNode params) {
        if (!properties.isEnabled()) {
            auditSpawnFailed(server, "stdio transport is disabled (agentshield.stdio.enabled=false)");
            return StdioRpcResult.error("stdio transport is disabled");
        }

        ManagedProcess managed;
        try {
            managed = getOrSpawn(server);
        } catch (StdioSpawnFailedException e) {
            return StdioRpcResult.error(e.getMessage());
        }

        boolean acquired;
        try {
            acquired = managed.callLock.tryLock(properties.getCallTimeoutSeconds(), TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return StdioRpcResult.error("interrupted while waiting for the stdio process");
        }
        if (!acquired) {
            return StdioRpcResult.error("stdio process for MCP server '" + server.getName()
                    + "' is busy with another call and timed out waiting");
        }
        try {
            return doCall(server, managed, method, params);
        } finally {
            managed.callLock.unlock();
        }
    }

    public McpDtos.McpTransportStatusResponse status(Long serverId) {
        ManagedProcess m = processes.get(serverId);
        if (m == null || !m.process.isAlive()) {
            return new McpDtos.McpTransportStatusResponse(false, null, null, null);
        }
        return new McpDtos.McpTransportStatusResponse(true, m.process.pid(), m.startedAt, m.lastActivityAt);
    }

    public McpOperationResult start(McpServer server) {
        if (!properties.isEnabled()) {
            return McpOperationResult.fail("stdio transport is disabled (agentshield.stdio.enabled=false)");
        }
        try {
            getOrSpawn(server);
            return McpOperationResult.ok();
        } catch (StdioSpawnFailedException e) {
            return McpOperationResult.fail(e.getMessage());
        }
    }

    public void stop(McpServer server) {
        ManagedProcess managed = processes.get(server.getId());
        if (managed == null) {
            return;
        }
        managed.callLock.lock();
        try {
            stopInternal(server.getId(), managed, "manual");
        } finally {
            managed.callLock.unlock();
        }
    }

    /** Stops any process idle longer than {@code agentshield.stdio.idle-timeout-minutes} (§4.5). */
    @Scheduled(fixedDelayString = "PT1M")
    public void reapIdleProcesses() {
        Instant cutoff = Instant.now().minus(Duration.ofMinutes(properties.getIdleTimeoutMinutes()));
        for (Map.Entry<Long, ManagedProcess> entry : processes.entrySet()) {
            ManagedProcess managed = entry.getValue();
            if (!managed.lastActivityAt.isBefore(cutoff)) {
                continue;
            }
            if (managed.callLock.tryLock()) {
                try {
                    if (managed.lastActivityAt.isBefore(cutoff)) {
                        stopInternal(entry.getKey(), managed, "idle");
                    }
                } finally {
                    managed.callLock.unlock();
                }
            }
        }
    }

    @PreDestroy
    void shutdown() {
        processes.forEach((id, managed) -> managed.process.destroyForcibly());
        ioExecutor.shutdownNow();
    }

    private ManagedProcess getOrSpawn(McpServer server) throws StdioSpawnFailedException {
        AtomicReference<StdioSpawnFailedException> failure = new AtomicReference<>();
        ManagedProcess result = processes.compute(server.getId(), (id, existing) -> {
            if (existing != null) {
                if (existing.process.isAlive()) {
                    return existing;
                }
                auditCrash(server, existing);
            }
            SpawnResult spawnResult = spawn(server);
            if (!spawnResult.success()) {
                failure.set(new StdioSpawnFailedException(spawnResult.errorMessage()));
                return null;
            }
            return spawnResult.managedProcess();
        });
        if (failure.get() != null) {
            throw failure.get();
        }
        return result;
    }

    private SpawnResult spawn(McpServer server) {
        var commandValidation = commandValidator.validate(server.getCommand());
        if (!commandValidation.allowed()) {
            auditSpawnFailed(server, commandValidation.reason());
            return SpawnResult.failure(commandValidation.reason());
        }
        if (processes.size() >= properties.getMaxConcurrentProcesses()) {
            String reason = "at capacity (" + properties.getMaxConcurrentProcesses() + " concurrent stdio processes)";
            auditSpawnFailed(server, reason);
            return SpawnResult.failure(reason);
        }

        Map<String, String> env;
        try {
            env = resolveEnvironment(server);
        } catch (StdioMissingEnvVarException e) {
            String reason = "required env var '" + e.variableName() + "' is not configured on the AgentShield process";
            auditSpawnFailed(server, reason);
            return SpawnResult.failure(reason);
        }

        Path sandboxDir;
        try {
            sandboxDir = Path.of(properties.getSandboxRoot(), "mcp-server-" + server.getId());
            Files.createDirectories(sandboxDir);
        } catch (IOException e) {
            String reason = "could not create sandbox directory: " + e.getMessage();
            auditSpawnFailed(server, reason);
            return SpawnResult.failure(reason);
        }

        List<String> commandAndArgs = new ArrayList<>();
        commandAndArgs.add(server.getCommand());
        if (server.getArgs() != null && !server.getArgs().isBlank()) {
            commandAndArgs.addAll(Arrays.asList(server.getArgs().trim().split("\\s+")));
        }

        ProcessBuilder pb = new ProcessBuilder(commandAndArgs);
        pb.directory(sandboxDir.toFile());
        pb.environment().clear();
        pb.environment().putAll(env);
        pb.redirectErrorStream(false);

        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            String reason = "failed to start stdio process: " + e.getMessage();
            auditSpawnFailed(server, reason);
            return SpawnResult.failure(reason);
        }

        ManagedProcess managed = new ManagedProcess(server.getId(), server.getName(), process, Instant.now());
        drainStderr(managed);

        auditRecorder.record("mcp.stdio_process_started", AuditSeverity.INFO,
                "stdio MCP server '" + server.getName() + "' process started (pid=" + process.pid() + ")",
                Map.of("sandboxDir", sandboxDir.toString()));
        return SpawnResult.success(managed);
    }

    /** Never inherits AgentShield's own environment — built from scratch, empty unless explicitly allowlisted (§5.2). */
    private Map<String, String> resolveEnvironment(McpServer server) throws StdioMissingEnvVarException {
        Map<String, String> env = new LinkedHashMap<>();
        if (server.getStdioEnvAllowlist() == null || server.getStdioEnvAllowlist().isBlank()) {
            return env;
        }
        for (String name : server.getStdioEnvAllowlist().split(",")) {
            String trimmed = name.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String value = System.getenv(trimmed);
            if (value == null) {
                throw new StdioMissingEnvVarException(trimmed);
            }
            env.put(trimmed, value);
        }
        return env;
    }

    private StdioRpcResult doCall(McpServer server, ManagedProcess managed, String method, JsonNode params) {
        long requestId = requestIdSeq.getAndIncrement();
        ObjectNode request = objectMapper.createObjectNode();
        request.put("jsonrpc", "2.0");
        request.put("id", requestId);
        request.put("method", method);
        request.set("params", params == null ? objectMapper.createObjectNode() : params);

        Future<StdioRpcResult> future = ioExecutor.submit(() -> {
            OutputStream stdin = managed.process.getOutputStream();
            stdin.write(objectMapper.writeValueAsString(request).getBytes(StandardCharsets.UTF_8));
            stdin.write('\n');
            stdin.flush();

            while (true) {
                String line = readLineWithLimit(managed.stdout, properties.getMaxOutputBytes());
                if (line == null) {
                    return StdioRpcResult.error("stdio process closed its output stream unexpectedly");
                }
                if (line.isBlank()) {
                    continue;
                }
                JsonNode responseJson;
                try {
                    responseJson = objectMapper.readTree(line);
                } catch (Exception e) {
                    continue; // stray non-JSON-RPC line on stdout; keep reading until timeout
                }
                if (!responseJson.has("id") || responseJson.get("id").asLong(-1) != requestId) {
                    continue;
                }
                if (responseJson.has("error")) {
                    return StdioRpcResult.error("stdio MCP server returned an error: " + responseJson.get("error"));
                }
                if (!responseJson.has("result")) {
                    return StdioRpcResult.error(
                            "response is not a valid JSON-RPC response (no \"result\" or \"error\" field)");
                }
                return StdioRpcResult.success(responseJson.get("result"));
            }
        });

        try {
            StdioRpcResult result = future.get(properties.getCallTimeoutSeconds(), TimeUnit.SECONDS);
            managed.lastActivityAt = Instant.now();
            return result;
        } catch (TimeoutException e) {
            future.cancel(true);
            stopInternal(server.getId(), managed, "call timeout");
            auditRecorder.record("mcp.stdio_call_timeout", AuditSeverity.WARNING,
                    "stdio call to MCP server '" + server.getName() + "' timed out after "
                            + properties.getCallTimeoutSeconds() + "s", null);
            return StdioRpcResult.error("stdio call to MCP server '" + server.getName() + "' timed out");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof StdioOutputLimitExceededException) {
                future.cancel(true);
                stopInternal(server.getId(), managed, "output size exceeded");
                auditRecorder.record("mcp.stdio_output_rejected", AuditSeverity.WARNING,
                        "stdio response from MCP server '" + server.getName()
                                + "' exceeded agentshield.stdio.max-output-bytes and was rejected", null);
                return StdioRpcResult.error("stdio response exceeded the maximum allowed size and was rejected");
            }
            future.cancel(true);
            stopInternal(server.getId(), managed, "I/O error");
            return StdioRpcResult.error("stdio call failed: " + (cause == null ? e.getMessage() : cause.getMessage()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return StdioRpcResult.error("interrupted while calling the stdio process");
        }
    }

    /**
     * Reads one newline-delimited JSON-RPC message, aborting if it exceeds {@code maxBytes}
     * before a newline is seen (§4.3) — a truncated line-based message can't be safely resumed,
     * so the caller kills the process rather than trying to resync.
     */
    private String readLineWithLimit(BufferedInputStream in, long maxBytes) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        long count = 0;
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                return buffer.toString(StandardCharsets.UTF_8).stripTrailing();
            }
            count++;
            if (count > maxBytes) {
                throw new StdioOutputLimitExceededException();
            }
            buffer.write(b);
        }
        return buffer.size() == 0 ? null : buffer.toString(StandardCharsets.UTF_8).stripTrailing();
    }

    private void drainStderr(ManagedProcess managed) {
        Thread t = new Thread(() -> {
            try (var reader = new BufferedReader(
                    new InputStreamReader(managed.process.getErrorStream(), StandardCharsets.UTF_8))) {
                StringBuilder tail = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    tail.append(line).append('\n');
                    if (tail.length() > 4000) {
                        tail.delete(0, tail.length() - 4000);
                    }
                    managed.stderrTail.set(tail.toString());
                }
            } catch (IOException ignored) {
                // process stream closed (process stopped/killed) — thread exits naturally
            }
        }, "stdio-mcp-stderr-drain-" + managed.serverId);
        t.setDaemon(true);
        t.start();
    }

    private void stopInternal(Long serverId, ManagedProcess managed, String reason) {
        processes.remove(serverId, managed);
        managed.process.destroyForcibly();
        auditRecorder.record("mcp.stdio_process_stopped", AuditSeverity.INFO,
                "stdio MCP server '" + managed.serverName + "' process stopped (reason=" + reason + ")", null);
    }

    private void auditCrash(McpServer server, ManagedProcess crashed) {
        int exitCode;
        try {
            exitCode = crashed.process.exitValue();
        } catch (IllegalThreadStateException e) {
            exitCode = -1;
        }
        auditRecorder.record("mcp.stdio_process_crashed", AuditSeverity.WARNING,
                "stdio MCP server '" + server.getName() + "' process exited unexpectedly (exitCode=" + exitCode + ")",
                Map.of("exitCode", exitCode, "stderrTail", crashed.stderrTail.get()));
    }

    private void auditSpawnFailed(McpServer server, String reason) {
        auditRecorder.record("mcp.stdio_process_spawn_failed", AuditSeverity.WARNING,
                "stdio MCP server '" + server.getName() + "' spawn failed: " + reason, null);
    }

    private static final class ManagedProcess {
        final Long serverId;
        final String serverName;
        final Process process;
        final BufferedInputStream stdout;
        final Instant startedAt;
        volatile Instant lastActivityAt;
        final ReentrantLock callLock = new ReentrantLock();
        final AtomicReference<String> stderrTail = new AtomicReference<>("");

        ManagedProcess(Long serverId, String serverName, Process process, Instant startedAt) {
            this.serverId = serverId;
            this.serverName = serverName;
            this.process = process;
            this.stdout = new BufferedInputStream(process.getInputStream());
            this.startedAt = startedAt;
            this.lastActivityAt = startedAt;
        }
    }

    private record SpawnResult(boolean success, ManagedProcess managedProcess, String errorMessage) {
        static SpawnResult success(ManagedProcess managedProcess) {
            return new SpawnResult(true, managedProcess, null);
        }

        static SpawnResult failure(String errorMessage) {
            return new SpawnResult(false, null, errorMessage);
        }
    }

    private static final class StdioSpawnFailedException extends RuntimeException {
        StdioSpawnFailedException(String message) {
            super(message);
        }
    }

    private static final class StdioMissingEnvVarException extends Exception {
        private final String variableName;

        StdioMissingEnvVarException(String variableName) {
            this.variableName = variableName;
        }

        String variableName() {
            return variableName;
        }
    }

    private static final class StdioOutputLimitExceededException extends IOException {
    }

    public record StdioRpcResult(boolean success, JsonNode result, String errorMessage) {
        static StdioRpcResult success(JsonNode result) {
            return new StdioRpcResult(true, result, null);
        }

        static StdioRpcResult error(String message) {
            return new StdioRpcResult(false, null, message);
        }
    }

}
