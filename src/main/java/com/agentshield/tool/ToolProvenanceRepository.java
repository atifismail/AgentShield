package com.agentshield.tool;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ToolProvenanceRepository extends JpaRepository<ToolProvenance, Long> {

    Optional<ToolProvenance> findByToolVersionId(Long toolVersionId);

    @Query("select p from ToolProvenance p where p.toolVersion.tool.id = :toolId order by p.toolVersion.detectedAt desc")
    java.util.List<ToolProvenance> findByToolIdOrderByVersionDetectedAtDesc(@Param("toolId") Long toolId);
}
