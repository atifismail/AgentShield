package com.agentshield.tool;

import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ToolVersionRepository extends JpaRepository<ToolVersion, Long> {

    List<ToolVersion> findByToolIdOrderByDetectedAtDesc(Long toolId);

    List<ToolVersion> findByDetectedAtBetweenOrderByDetectedAtDesc(Instant from, Instant to);
}
