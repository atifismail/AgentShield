package com.agentshield.approval;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.agentshield.approval.ApprovalProfileDtos.CreateApprovalProfileRequest;
import com.agentshield.audit.AuditService;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ValidationException;
import com.agentshield.security.UserRole;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class ApprovalProfileServiceTest {

    private final ApprovalProfileRepository repository = Mockito.mock(ApprovalProfileRepository.class);
    private final AuditService auditService = Mockito.mock(AuditService.class);
    private final ApprovalProfileService service = new ApprovalProfileService(repository, auditService);

    private CreateApprovalProfileRequest request(String name, int priority) {
        return new CreateApprovalProfileRequest(name, "desc", priority, null, null, null, null, null, null,
                UserRole.APPROVER, null);
    }

    @Test
    void createRejectsADuplicateName() {
        when(repository.existsByName("dup")).thenReturn(true);

        assertThatThrownBy(() -> service.create(request("dup", 10), "admin")).isInstanceOf(ConflictException.class);
    }

    @Test
    void createSucceedsWhenNoAmbiguityExists() {
        when(repository.findByPriorityAndEnabledTrue(10)).thenReturn(List.of());
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        ApprovalProfile profile = service.create(request("unique", 10), "admin");

        assertThat(profile.getName()).isEqualTo("unique");
        assertThat(profile.isEnabled()).isTrue();
    }

    @Test
    void createRejectsAnIdenticalPredicateProfileAtTheSamePriority() {
        ApprovalProfile existing = new ApprovalProfile();
        existing.setId(1L);
        existing.setName("existing");
        existing.setPriority(10);
        existing.setEnabled(true);
        when(repository.findByPriorityAndEnabledTrue(10)).thenReturn(List.of(existing));

        assertThatThrownBy(() -> service.create(request("new-one", 10), "admin"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("ambiguous");
    }

    @Test
    void createAllowsDifferentPredicatesAtTheSamePriority() {
        ApprovalProfile existing = new ApprovalProfile();
        existing.setId(1L);
        existing.setName("existing");
        existing.setPriority(10);
        existing.setEnabled(true);
        existing.setToolGroup("saas");
        when(repository.findByPriorityAndEnabledTrue(10)).thenReturn(List.of(existing));
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        var req = new CreateApprovalProfileRequest("new-one", null, 10, null, null, "database", null, null, null,
                UserRole.APPROVER, null);
        ApprovalProfile profile = service.create(req, "admin");

        assertThat(profile.getToolGroup()).isEqualTo("database");
    }
}
