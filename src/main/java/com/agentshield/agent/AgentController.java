package com.agentshield.agent;

import com.agentshield.agent.AgentDtos.AgentResponse;
import com.agentshield.agent.AgentDtos.AgentTokenResponse;
import com.agentshield.agent.AgentDtos.CreateAgentRequest;
import com.agentshield.agent.AgentDtos.UpdateAgentRequest;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/agents")
public class AgentController {

    private final AgentService agentService;

    public AgentController(AgentService agentService) {
        this.agentService = agentService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public AgentResponse create(@Valid @RequestBody CreateAgentRequest request) {
        return AgentResponse.from(agentService.create(request));
    }

    @GetMapping
    public List<AgentResponse> list() {
        return agentService.list().stream().map(AgentResponse::from).toList();
    }

    @GetMapping("/{id}")
    public AgentResponse get(@PathVariable Long id) {
        return AgentResponse.from(agentService.get(id));
    }

    @PutMapping("/{id}")
    public AgentResponse update(@PathVariable Long id, @RequestBody UpdateAgentRequest request) {
        return AgentResponse.from(agentService.update(id, request));
    }

    @PostMapping("/{id}/enable")
    public AgentResponse enable(@PathVariable Long id) {
        return AgentResponse.from(agentService.setEnabled(id, true));
    }

    @PostMapping("/{id}/disable")
    public AgentResponse disable(@PathVariable Long id) {
        return AgentResponse.from(agentService.setEnabled(id, false));
    }

    @PostMapping("/{id}/rotate-token")
    public AgentTokenResponse rotateToken(@PathVariable Long id) {
        return new AgentTokenResponse(id, agentService.rotateToken(id));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id) {
        agentService.setEnabled(id, false);
    }
}
