package com.agentshield.tool;

import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ToolRepository extends JpaRepository<Tool, Long> {

    Optional<Tool> findByName(String name);

    long countByApprovalStatus(ToolApprovalStatus status);

    List<Tool> findByApprovalStatus(ToolApprovalStatus status);

    Page<Tool> findByMcpServerId(Long mcpServerId, Pageable pageable);

    Page<Tool> findByMcpServerIdAndApprovalStatus(Long mcpServerId, ToolApprovalStatus approvalStatus, Pageable pageable);

    /** Resolves a tool by the identity a specific MCP server's proxy call addresses it by. */
    Optional<Tool> findByMcpServerIdAndMcpToolName(Long mcpServerId, String mcpToolName);
}
