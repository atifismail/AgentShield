package com.agentshield.gateway;

import com.agentshield.gateway.GatewayDtos.InvokeRequest;
import com.agentshield.gateway.GatewayDtos.InvokeResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/gateway")
public class GatewayController {

    private final GatewayService gatewayService;

    public GatewayController(GatewayService gatewayService) {
        this.gatewayService = gatewayService;
    }

    @PostMapping("/invoke")
    public InvokeResponse invoke(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @Valid @RequestBody InvokeRequest request) {
        return gatewayService.invoke(authorization, request);
    }
}
