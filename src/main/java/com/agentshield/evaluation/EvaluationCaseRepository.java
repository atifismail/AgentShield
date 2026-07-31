package com.agentshield.evaluation;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EvaluationCaseRepository extends JpaRepository<EvaluationCase, Long> {

    List<EvaluationCase> findBySuiteIdOrderById(Long suiteId);
}
