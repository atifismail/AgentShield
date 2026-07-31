package com.agentshield.evaluation;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EvaluationResultRepository extends JpaRepository<EvaluationResult, Long> {

    List<EvaluationResult> findByRunIdOrderById(Long runId);
}
