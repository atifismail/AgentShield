package com.agentshield.gateway;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class GatewayRequestPageController {

    private final GatewayRequestRepository repository;

    public GatewayRequestPageController(GatewayRequestRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/gateway-requests")
    public String list(@RequestParam(defaultValue = "0") int page, Model model) {
        model.addAttribute("pageTitle", "Gateway Requests");
        model.addAttribute("requestsPage",
                repository.findAllByOrderByCreatedAtDesc(PageRequest.of(page, 50, Sort.by(Sort.Direction.DESC, "createdAt"))));
        return "gateway-requests/index";
    }
}
