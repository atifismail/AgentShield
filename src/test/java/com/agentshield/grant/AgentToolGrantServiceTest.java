package com.agentshield.grant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.agentshield.agent.Agent;
import com.agentshield.audit.AuditService;
import com.agentshield.agent.AgentRepository;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ResourceNotFoundException;
import com.agentshield.common.ValidationException;
import com.agentshield.grant.GrantDtos.CreateGrantRequest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class AgentToolGrantServiceTest {

    private final AgentToolGrantRepository repository = Mockito.mock(AgentToolGrantRepository.class);
    private final AgentRepository agentRepository = Mockito.mock(AgentRepository.class);
    private final ToolRepository toolRepository = Mockito.mock(ToolRepository.class);
    private final AuditService auditService = Mockito.mock(AuditService.class);
    private final AgentToolGrantService service = new AgentToolGrantService(repository, agentRepository,
            toolRepository, auditService);

    private Agent agent() {
        Agent agent = new Agent();
        agent.setId(1L);
        agent.setName("test-agent");
        return agent;
    }

    private Tool tool() {
        Tool tool = new Tool();
        tool.setId(2L);
        tool.setName("test-tool");
        return tool;
    }

    private void stubExistingAgentAndTool() {
        when(agentRepository.findById(1L)).thenReturn(Optional.of(agent()));
        when(toolRepository.findById(2L)).thenReturn(Optional.of(tool()));
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void createRejectsUnknownAgent() {
        when(agentRepository.findById(1L)).thenReturn(Optional.empty());
        var request = new CreateGrantRequest(2L, null, null, null, null, null, null, null);

        assertThatThrownBy(() -> service.create(1L, request, "admin")).isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void createRejectsUnknownTool() {
        when(agentRepository.findById(1L)).thenReturn(Optional.of(agent()));
        when(toolRepository.findById(2L)).thenReturn(Optional.empty());
        var request = new CreateGrantRequest(2L, null, null, null, null, null, null, null);

        assertThatThrownBy(() -> service.create(1L, request, "admin")).isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void createRejectsExpiresAtNotAfterNotBefore() {
        stubExistingAgentAndTool();
        Instant now = Instant.now();
        var request = new CreateGrantRequest(2L, null, null, null, null, now, now.minus(1, ChronoUnit.HOURS), null);

        assertThatThrownBy(() -> service.create(1L, request, "admin")).isInstanceOf(ValidationException.class);
    }

    @Test
    void createRejectsAMalformedResourcePathPattern() {
        stubExistingAgentAndTool();
        var request = new CreateGrantRequest(2L, null, null, "/repos/**", null, null, null, null);

        assertThatThrownBy(() -> service.create(1L, request, "admin")).isInstanceOf(ValidationException.class);
    }

    @Test
    void createNormalizesBlankStringsToNull() {
        stubExistingAgentAndTool();
        var request = new CreateGrantRequest(2L, null, "   ", null, "  ", null, null, "  ");

        AgentToolGrant grant = service.create(1L, request, "admin");

        assertThat(grant.getTargetEnvironment()).isNull();
        assertThat(grant.getRequiredTokenScope()).isNull();
        assertThat(grant.getReason()).isNull();
        assertThat(grant.getStatus()).isEqualTo(GrantStatus.ACTIVE);
    }

    @Test
    void createSucceedsWithAValidResourcePathPattern() {
        stubExistingAgentAndTool();
        var request = new CreateGrantRequest(2L, null, "DEV", "/repos/*/pulls", null, null, null, null);

        AgentToolGrant grant = service.create(1L, request, "admin");

        assertThat(grant.getResourcePathPattern()).isEqualTo("/repos/*/pulls");
        assertThat(grant.getCreatedBy()).isEqualTo("admin");
    }

    @Test
    void revokeRejectsAnAlreadyRevokedGrant() {
        AgentToolGrant grant = new AgentToolGrant();
        grant.setId(10L);
        grant.setAgentId(1L);
        grant.setStatus(GrantStatus.REVOKED);
        when(repository.findByIdAndAgentId(10L, 1L)).thenReturn(Optional.of(grant));

        assertThatThrownBy(() -> service.revoke(1L, 10L, "no longer needed", "admin"))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void revokeSetsRevokedByAndTimestamp() {
        AgentToolGrant grant = new AgentToolGrant();
        grant.setId(10L);
        grant.setAgentId(1L);
        grant.setStatus(GrantStatus.ACTIVE);
        when(repository.findByIdAndAgentId(10L, 1L)).thenReturn(Optional.of(grant));

        AgentToolGrant revoked = service.revoke(1L, 10L, "compromised", "security-analyst-1");

        assertThat(revoked.getStatus()).isEqualTo(GrantStatus.REVOKED);
        assertThat(revoked.getRevokedBy()).isEqualTo("security-analyst-1");
        assertThat(revoked.getRevokedAt()).isNotNull();
        assertThat(revoked.getReason()).isEqualTo("compromised");
    }

    @Test
    void listRejectsUnknownAgent() {
        when(agentRepository.findById(1L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.list(1L)).isInstanceOf(ResourceNotFoundException.class);
    }
}
