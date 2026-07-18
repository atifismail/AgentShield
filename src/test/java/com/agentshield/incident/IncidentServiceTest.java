package com.agentshield.incident;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.common.IncidentStatus;
import com.agentshield.common.ResourceNotFoundException;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class IncidentServiceTest {

    private final IncidentRepository repository = Mockito.mock(IncidentRepository.class);
    private final IncidentService service = new IncidentService(repository);

    @Test
    void updateStatusTransitionsAndPersists() {
        Incident incident = new Incident();
        incident.setId(1L);
        incident.setStatus(IncidentStatus.OPEN);
        Mockito.when(repository.findById(1L)).thenReturn(Optional.of(incident));
        Mockito.when(repository.save(Mockito.any())).thenAnswer(inv -> inv.getArgument(0));

        Incident updated = service.updateStatus(1L, IncidentStatus.ACKNOWLEDGED);

        assertThat(updated.getStatus()).isEqualTo(IncidentStatus.ACKNOWLEDGED);
    }

    @Test
    void updateStatusThrowsWhenIncidentMissing() {
        Mockito.when(repository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.updateStatus(99L, IncidentStatus.RESOLVED))
                .isInstanceOf(ResourceNotFoundException.class);
    }
}
