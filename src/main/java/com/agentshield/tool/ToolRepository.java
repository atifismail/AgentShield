package com.agentshield.tool;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ToolRepository extends JpaRepository<Tool, Long> {

    Optional<Tool> findByName(String name);

    long countByApprovalStatus(ToolApprovalStatus status);
}
