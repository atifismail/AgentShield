package com.agentshield.mcp;

import com.agentshield.mcp.McpDtos.DiscoveryResponse;
import com.agentshield.mcp.McpDtos.McpServerResponse;
import com.agentshield.mcp.McpDtos.RegisterMcpServerRequest;
import com.agentshield.tool.Tool;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/mcp-servers")
public class McpServerController {

    private final McpDiscoveryService discoveryService;

    public McpServerController(McpDiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
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

    @PostMapping("/{id}/discover")
    public DiscoveryResponse discover(@PathVariable Long id) {
        var result = discoveryService.discover(id);
        return new DiscoveryResponse(
                result.discoveredOrUpdated().stream().map(Tool::getName).toList(),
                result.removed().stream().map(Tool::getName).toList());
    }
}
