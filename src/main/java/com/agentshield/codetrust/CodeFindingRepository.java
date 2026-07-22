package com.agentshield.codetrust;

import com.agentshield.common.RiskLevel;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CodeFindingRepository extends JpaRepository<CodeFinding, Long> {

    List<CodeFinding> findByAssessmentId(Long assessmentId);

    boolean existsByAssessmentIdAndSeverityIn(Long assessmentId, List<RiskLevel> severities);
}
