package com.agentshield.mcp;

import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.ValidationException;
import com.agentshield.gateway.GatewayDtos.InvokeRequest;
import com.agentshield.gateway.GatewayDtos.InvokeResponse;
import com.agentshield.gateway.GatewayService;
import com.agentshield.mcp.McpDtos.DiscoveryResponse;
import com.agentshield.mcp.McpDtos.McpProxyInvokeRequest;
import com.agentshield.mcp.McpDtos.McpServerResponse;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.mcp.McpDtos.McpTransportStatusResponse;
import com.agentshield.mcp.McpDtos.UpdateMcpAuthRequest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolDtos.ToolResponse;
import com.agentshield.tool.ToolRepository;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/mcp-servers")
@Tag(name = "MCP servers", description = "Registers MCP servers and discovers their tools via JSON-RPC; discovered tools flow into the same tool registry/approval/gateway pipeline as plain HTTP tools.")
public class McpServerController {

    private final McpDiscoveryService discoveryService;
    private final StdioMcpProcessManager stdioProcessManager;
    private final McpSseConnectionManager sseConnectionManager;
    private final ToolRepository toolRepository;
    private final GatewayService gatewayService;

    public McpServerController(McpDiscoveryService discoveryService, StdioMcpProcessManager stdioProcessManager,
            McpSseConnectionManager sseConnectionManager, ToolRepository toolRepository, GatewayService gatewayService) {
        this.discoveryService = discoveryService;
        this.stdioProcessManager = stdioProcessManager;
        this.sseConnectionManager = sseConnectionManager;
        this.toolRepository = toolRepository;
        this.gatewayService = gatewayService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public McpServerResponse register(@Valid @RequestBody RegisterMcpServerRequest request) {
        return McpServerResponse.from(discoveryService.register(request));
    }

    @GetMapping
    public List<McpServerResponse> list() {
        return discoveryService.list().stream().map(McpServerResponse::from).toList();
    }

    @GetMapping("/{id}")
    public McpServerResponse get(@PathVariable Long id) {
        return McpServerResponse.from(discoveryService.get(id));
    }

    @PatchMapping("/{id}/auth")
    public McpServerResponse updateAuth(@PathVariable Long id, @Valid @RequestBody UpdateMcpAuthRequest request) {
        return McpServerResponse.from(discoveryService.updateAuth(id, request));
    }

    @PostMapping("/{id}/discover")
    public DiscoveryResponse discover(@PathVariable Long id) {
        var result = discoveryService.discover(id);
        return new DiscoveryResponse(
                result.discoveredOrUpdated().stream().map(Tool::getName).toList(),
                result.removed().stream().map(Tool::getName).toList());
    }

    @GetMapping("/{id}/stdio/status")
    public McpTransportStatusResponse stdioStatus(@PathVariable Long id) {
        McpServer server = discoveryService.get(id);
        return stdioProcessManager.status(server.getId());
    }

    @PostMapping("/{id}/stdio/start")
    public McpTransportStatusResponse stdioStart(@PathVariable Long id) {
        McpServer server = discoveryService.get(id);
        var result = stdioProcessManager.start(server);
        if (!result.success()) {
            throw new ValidationException(result.errorMessage());
        }
        return stdioProcessManager.status(server.getId());
    }

    @PostMapping("/{id}/stdio/stop")
    public McpTransportStatusResponse stdioStop(@PathVariable Long id) {
        McpServer server = discoveryService.get(id);
        stdioProcessManager.stop(server);
        return stdioProcessManager.status(server.getId());
    }

    @GetMapping("/{id}/sse/status")
    public McpTransportStatusResponse sseStatus(@PathVariable Long id) {
        McpServer server = discoveryService.get(id);
        return sseConnectionManager.status(server.getId());
    }

    @PostMapping("/{id}/sse/start")
    public McpTransportStatusResponse sseStart(@PathVariable Long id) {
        McpServer server = discoveryService.get(id);
        var result = sseConnectionManager.start(server);
        if (!result.success()) {
            throw new ValidationException(result.errorMessage());
        }
        return sseConnectionManager.status(server.getId());
    }

    @PostMapping("/{id}/sse/stop")
    public McpTransportStatusResponse sseStop(@PathVariable Long id) {
        McpServer server = discoveryService.get(id);
        sseConnectionManager.stop(server);
        return sseConnectionManager.status(server.getId());
    }

    /**
     * MCP-scoped tool listing (agentshield_policy_evidence_execution_plan_2026-07-30.md work
     * package 1) — the same tool rows {@code GET /api/tools} already exposes, filtered to this
     * server and paginated. Additive: it does not replace the generic listing.
     */
    @GetMapping("/{id}/tools")
    public Page<ToolResponse> tools(@PathVariable Long id,
            @RequestParam(required = false) ToolApprovalStatus approvalStatus,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        discoveryService.get(id);
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<Tool> tools = approvalStatus == null
                ? toolRepository.findByMcpServerId(id, pageable)
                : toolRepository.findByMcpServerIdAndApprovalStatus(id, approvalStatus, pageable);
        return tools.map(ToolResponse::from);
    }

    /**
     * Thin server-addressing adapter over the generic {@code POST /api/gateway/invoke} path
     * (see {@link McpProxyInvokeRequest}). Resolves {@code toolName} to an existing registered
     * {@code Tool} scoped to this server, then delegates unchanged to
     * {@link GatewayService#invoke} — the exact same credential, policy, DLP, audit, and approval
     * pipeline a generic gateway call goes through, never bypassed.
     */
    @PostMapping("/{id}/proxy")
    public InvokeResponse proxy(@PathVariable Long id,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @Valid @RequestBody McpProxyInvokeRequest request) {
        discoveryService.get(id);
        Tool tool = toolRepository.findByMcpServerIdAndMcpToolName(id, request.toolName())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "MCP server " + id + " has no tool named '" + request.toolName() + "'"));
        InvokeRequest invokeRequest = new InvokeRequest(null, tool.getName(), request.action(),
                request.actionCategory(), request.targetEnvironment(), request.input(), request.context());
        return gatewayService.invoke(authorization, invokeRequest);
    }
}
