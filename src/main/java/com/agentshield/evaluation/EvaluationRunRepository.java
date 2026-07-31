package com.agentshield.evaluation;

import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EvaluationRunRepository extends JpaRepository<EvaluationRun, Long> {

    List<EvaluationRun> findBySuiteIdOrderByStartedAtDesc(Long suiteId);

    List<EvaluationRun> findAllByOrderByStartedAtDesc();

    /** Evidence export (work package 5). */
    List<EvaluationRun> findByStartedAtBetweenOrderByStartedAtDesc(Instant from, Instant to);
}
