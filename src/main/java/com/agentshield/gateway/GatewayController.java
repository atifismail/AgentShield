package com.agentshield.gateway;

import com.agentshield.gateway.GatewayDtos.InvokeRequest;
import com.agentshield.gateway.GatewayDtos.InvokeResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/gateway")
@Tag(name = "Gateway", description = "The single entry point agents call: authenticate, evaluate policy + risk, "
        + "forward to the tool if allowed, scan the response, and return ALLOW/DENY/APPROVAL_REQUIRED.")
public class GatewayController {

    private final GatewayService gatewayService;

    public GatewayController(GatewayService gatewayService) {
        this.gatewayService = gatewayService;
    }

    @PostMapping("/invoke")
    @SecurityRequirement(name = "agentBearerToken")
    @Operation(summary = "Invoke a tool through the gateway",
            description = "Every real tool call an agent makes goes through this endpoint. Examples below mirror "
                    + "the bundled demo attack lab (docs/demo-lab.md) — try them against a locally running instance.")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(content = @Content(
            examples = {
                    @ExampleObject(name = "Allowed read", summary = "A routine, low-risk call",
                            value = "{\"toolId\":\"mock-git\",\"action\":\"log\",\"actionCategory\":\"READ\","
                                    + "\"targetEnvironment\":\"DEV\",\"input\":{}}"),
                    @ExampleObject(name = "Destructive PROD action", summary = "Blocked outright — never auto-allowed",
                            value = "{\"toolId\":\"mock-database\",\"action\":\"deleteRecords\","
                                    + "\"actionCategory\":\"DESTRUCTIVE\",\"targetEnvironment\":\"PROD\","
                                    + "\"input\":{\"table\":\"users\"}}"),
                    @ExampleObject(name = "External transfer of a secret-bearing table",
                            summary = "Requires approval, then the response scanner blocks execution",
                            value = "{\"toolId\":\"mock-database\",\"action\":\"query\","
                                    + "\"actionCategory\":\"EXTERNAL_TRANSFER\",\"targetEnvironment\":\"DEV\","
                                    + "\"input\":{\"table\":\"internal_credentials\"}}")
            }))
    public InvokeResponse invoke(
            @Schema(description = "Agent bearer token: 'Bearer <token>'") @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @Valid @RequestBody InvokeRequest request) {
        return gatewayService.invoke(authorization, request);
    }
}
