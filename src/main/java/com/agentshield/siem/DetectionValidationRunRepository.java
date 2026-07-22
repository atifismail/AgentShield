package com.agentshield.siem;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DetectionValidationRunRepository extends JpaRepository<DetectionValidationRun, Long> {

    Optional<DetectionValidationRun> findTopByScenarioCodeOrderByCreatedAtDesc(String scenarioCode);

    List<DetectionValidationRun> findAllByOrderByCreatedAtDesc();
}
