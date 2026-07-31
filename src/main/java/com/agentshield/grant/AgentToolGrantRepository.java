package com.agentshield.grant;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AgentToolGrantRepository extends JpaRepository<AgentToolGrant, Long> {

    List<AgentToolGrant> findByAgentIdOrderByCreatedAtDesc(Long agentId);

    List<AgentToolGrant> findByAgentIdAndToolId(Long agentId, Long toolId);

    boolean existsByAgentIdAndToolId(Long agentId, Long toolId);

    Optional<AgentToolGrant> findByIdAndAgentId(Long id, Long agentId);
}
