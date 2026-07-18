package com.agentshield.incident;

import com.agentshield.common.IncidentStatus;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    List<Incident> findTop5ByOrderByCreatedAtDesc();

    long countByStatus(IncidentStatus status);

    Page<Incident> findAllByOrderByCreatedAtDesc(Pageable pageable);
}
