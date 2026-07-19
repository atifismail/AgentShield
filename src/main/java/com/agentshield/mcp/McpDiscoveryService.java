package com.agentshield.mcp;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.TokenHasher;
import com.agentshield.common.ValidationException;
import com.agentshield.gateway.OutboundEndpointValidator;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolService;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.StreamSupport;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Registers MCP servers and discovers their tools (improvement_plan.md #6). Discovered tools
 * become regular {@code tools} rows (type=MCP), reusing the existing drift-detection and
 * approval workflow untouched — an admin approves a newly-discovered or drifted MCP tool exactly
 * like they would any other tool.
 */
@Service
public class McpDiscoveryService {

    private final McpServerRepository serverRepository;
    private final ToolRepository toolRepository;
    private final ToolService toolService;
    private final McpJsonRpcClient rpcClient;
    private final McpOAuthTokenService oauthTokenService;
    private final OutboundEndpointValidator outboundEndpointValidator;
    private final StdioCommandValidator stdioCommandValidator;
    private final StdioMcpProcessManager stdioProcessManager;
    private final StdioMcpProperties stdioProperties;
    private final AuditService auditService;

    public McpDiscoveryService(McpServerRepository serverRepository, ToolRepository toolRepository,
            ToolService toolService, McpJsonRpcClient rpcClient, McpOAuthTokenService oauthTokenService,
            OutboundEndpointValidator outboundEndpointValidator, StdioCommandValidator stdioCommandValidator,
            StdioMcpProcessManager stdioProcessManager, StdioMcpProperties stdioProperties, AuditService auditService) {
        this.serverRepository = serverRepository;
        this.toolRepository = toolRepository;
        this.toolService = toolService;
        this.rpcClient = rpcClient;
        this.oauthTokenService = oauthTokenService;
        this.outboundEndpointValidator = outboundEndpointValidator;
        this.stdioCommandValidator = stdioCommandValidator;
        this.stdioProcessManager = stdioProcessManager;
        this.stdioProperties = stdioProperties;
        this.auditService = auditService;
    }

    @Transactional
    public McpServer register(RegisterMcpServerRequest request) {
        serverRepository.findByName(request.name()).ifPresent(s -> {
            throw new ValidationException("an MCP server named '" + request.name() + "' already exists");
        });
        if (request.transportType() == McpTransportType.HTTP) {
            var validation = outboundEndpointValidator.validate(request.endpointUrl());
            if (!validation.allowed()) {
                throw new ValidationException("endpoint URL rejected by outbound policy: " + validation.reason());
            }
        }
        if (request.transportType() == McpTransportType.STDIO) {
            if (!stdioProperties.isEnabled()) {
                throw new ValidationException(
                        "stdio transport is disabled (agentshield.stdio.enabled=false); a STDIO server cannot be registered");
            }
            var commandValidation = stdioCommandValidator.validate(request.command());
            if (!commandValidation.allowed()) {
                throw new ValidationException("stdio command rejected: " + commandValidation.reason());
            }
        }
        McpServer server = new McpServer();
        server.setName(request.name());
        server.setTransportType(request.transportType());
        server.setEndpointUrl(request.endpointUrl());
        server.setCommand(request.command());
        server.setArgs(request.args());
        server.setStdioEnvAllowlist(request.stdioEnvAllowlist());
        server.setOwner(request.owner());
        server.setEnvironment(request.environment());
        server.setToolGroup(request.toolGroup() == null || request.toolGroup().isBlank() ? "default" : request.toolGroup());
        server = serverRepository.save(server);

        auditService.record(null, "mcp.server_registered", ActorType.USER, request.owner(), null, null,
                AuditSeverity.INFO, "MCP server '" + server.getName() + "' registered (" + server.getTransportType() + ")",
                null);
        return server;
    }

    public McpServer get(Long id) {
        return serverRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("MCP server " + id + " not found"));
    }

    public List<McpServer> list() {
        return serverRepository.findAll();
    }

    /**
     * Sets how AgentShield authenticates itself to this server (design-mcp-authorization.md §4,
     * §9). Separate from {@link #register} since it's typically configured once, after initial
     * registration, by an operator who owns the relationship with the MCP server's authorization
     * server.
     */
    @Transactional
    public McpServer updateAuth(Long id, McpDtos.UpdateMcpAuthRequest request) {
        McpServer server = get(id);
        server.setAuthMode(request.authMode());
        server.setOauthIssuer(request.oauthIssuer());
        server.setOauthResource(request.oauthResource());
        server.setOauthTokenEndpoint(request.oauthTokenEndpoint());
        server.setOauthClientId(request.oauthClientId());
        server.setOauthClientSecretRef(request.oauthClientSecretRef());
        server.setOauthScopes(request.oauthScopes());
        server.touch();
        server = serverRepository.save(server);
        auditService.record(null, "mcp.server_auth_updated", ActorType.USER, null, null, null, AuditSeverity.INFO,
                "MCP server '" + server.getName() + "' auth mode set to " + server.getAuthMode(), null);
        return server;
    }

    /**
     * Calls {@code tools/list}, upserts a {@code Tool} row per discovered tool (new tools start
     * PENDING; changed ones flip to DRIFTED via the existing fingerprint logic), and marks any
     * previously-discovered tool no longer present as REJECTED ("removed").
     */
    @Transactional
    public DiscoveryResult discover(Long serverId) {
        McpServer server = get(serverId);
        if (server.getTransportType() != McpTransportType.HTTP && server.getTransportType() != McpTransportType.STDIO) {
            throw new ValidationException(
                    "discovery for transport " + server.getTransportType()
                            + " is not implemented yet; only HTTP and STDIO are supported");
        }

        var rpcResult = callRpc(server, "tools/list", null);
        if (!rpcResult.success()) {
            auditService.record(null, "mcp.discovery_failed", ActorType.SYSTEM, "mcp-discovery", null, null,
                    AuditSeverity.WARNING, "discovery failed for MCP server '" + server.getName() + "': "
                            + rpcResult.errorMessage(), null);
            throw new ValidationException("MCP discovery failed: " + rpcResult.errorMessage());
        }

        JsonNode toolsNode = rpcResult.result() != null ? rpcResult.result().path("tools") : null;
        List<JsonNode> discoveredTools = toolsNode != null && toolsNode.isArray()
                ? StreamSupport.stream(toolsNode.spliterator(), false).toList()
                : List.of();

        Set<String> discoveredNames = new HashSet<>();
        List<Tool> upserted = new ArrayList<>();
        StringBuilder fingerprintInput = new StringBuilder();

        for (JsonNode toolNode : discoveredTools) {
            String mcpToolName = toolNode.path("name").asText(null);
            if (mcpToolName == null || mcpToolName.isBlank()) {
                continue;
            }
            String description = toolNode.path("description").asText("");
            JsonNode inputSchema = toolNode.path("inputSchema");
            String schemaJson = inputSchema.isMissingNode() ? "{}" : inputSchema.toString();
            String qualifiedName = server.getName() + ":" + mcpToolName;
            discoveredNames.add(qualifiedName);
            fingerprintInput.append(qualifiedName).append('|').append(description).append('|').append(schemaJson).append(';');

            Tool tool = toolService.upsertDiscoveredTool(qualifiedName, ToolType.MCP, server.getToolGroup(),
                    server.getEndpointUrl(), server.getOwner(), server.getEnvironment(), description, schemaJson,
                    server.getId(), mcpToolName);
            upserted.add(tool);
        }

        List<Tool> removed = new ArrayList<>();
        for (Tool existing : toolRepository.findAll()) {
            if (server.getId().equals(existing.getMcpServerId()) && !discoveredNames.contains(existing.getName())) {
                toolService.rejectLatestVersion(existing.getId(), "system (mcp-discovery: tool no longer present)");
                removed.add(existing);
            }
        }

        server.setDiscoveredToolsHash(TokenHasher.sha256Hex(fingerprintInput.toString()));
        server.setLastDiscoveredAt(Instant.now());
        server.touch();

        auditService.record(null, "mcp.discovery_completed", ActorType.SYSTEM, "mcp-discovery", null, null,
                AuditSeverity.INFO,
                "MCP server '" + server.getName() + "' discovery: " + upserted.size() + " tool(s) seen, "
                        + removed.size() + " removed", null);

        return new DiscoveryResult(upserted, removed);
    }

    /** Dispatches a JSON-RPC call by transport — STDIO goes through the sandboxed process manager, HTTP through {@link McpJsonRpcClient}. */
    private McpJsonRpcClient.McpRpcResult callRpc(McpServer server, String method, JsonNode params) {
        if (server.getTransportType() == McpTransportType.STDIO) {
            var result = stdioProcessManager.call(server, method, params);
            return result.success() ? McpJsonRpcClient.McpRpcResult.success(result.result())
                    : McpJsonRpcClient.McpRpcResult.error(result.errorMessage());
        }
        String bearerToken = null;
        if (server.getAuthMode() == McpAuthMode.OAUTH2) {
            var tokenResult = oauthTokenService.getValidToken(server);
            if (!tokenResult.success()) {
                return McpJsonRpcClient.McpRpcResult.error("could not obtain an OAuth token for MCP server '"
                        + server.getName() + "': " + tokenResult.errorMessage());
            }
            bearerToken = tokenResult.accessToken();
        }
        return rpcClient.call(server.getEndpointUrl(), method, params, bearerToken);
    }

    public record DiscoveryResult(List<Tool> discoveredOrUpdated, List<Tool> removed) {
    }
}
