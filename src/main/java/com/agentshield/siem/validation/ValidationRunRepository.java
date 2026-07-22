package com.agentshield.siem.validation;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ValidationRunRepository extends JpaRepository<ValidationRun, Long> {

    List<ValidationRun> findAllByOrderByCreatedAtDesc();
}
