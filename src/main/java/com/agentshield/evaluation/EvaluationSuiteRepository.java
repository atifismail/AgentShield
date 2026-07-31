package com.agentshield.evaluation;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EvaluationSuiteRepository extends JpaRepository<EvaluationSuite, Long> {

    List<EvaluationSuite> findByNameOrderByVersionDesc(String name);

    Optional<EvaluationSuite> findTopByNameOrderByVersionDesc(String name);

    Optional<EvaluationSuite> findByNameAndVersion(String name, int version);
}
