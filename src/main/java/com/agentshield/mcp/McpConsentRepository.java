package com.agentshield.mcp;

import com.agentshield.common.ActionCategory;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface McpConsentRepository extends JpaRepository<McpConsent, Long> {

    /**
     * A matching consent covers every tool/category (null-scoped) or the exact tool/category
     * requested — the same "null means any" convention {@code PolicyOverride} already uses.
     * {@code toolName}/{@code actionCategory} are always concrete (non-null) values from the
     * caller here, so this doesn't hit the Postgres bind-parameter-type-inference issue that
     * affects genuinely-nullable-parameter comparisons elsewhere in this codebase.
     */
    @Query("select c from McpConsent c where c.agent.id = :agentId and c.mcpServer.id = :mcpServerId "
            + "and c.status = com.agentshield.mcp.ConsentStatus.ACTIVE "
            + "and (c.expiresAt is null or c.expiresAt > :now) "
            + "and (c.toolName is null or c.toolName = :toolName) "
            + "and (c.actionCategory is null or c.actionCategory = :actionCategory)")
    List<McpConsent> findMatching(@Param("agentId") Long agentId, @Param("mcpServerId") Long mcpServerId,
            @Param("toolName") String toolName, @Param("actionCategory") ActionCategory actionCategory,
            @Param("now") Instant now);

    List<McpConsent> findByAgentIdOrderByGrantedAtDesc(Long agentId);

    List<McpConsent> findByMcpServerIdOrderByGrantedAtDesc(Long mcpServerId);

    List<McpConsent> findAllByOrderByGrantedAtDesc();

    List<McpConsent> findByStatus(ConsentStatus status);
}
