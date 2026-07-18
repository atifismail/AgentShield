package com.agentshield.agent;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AgentRepository extends JpaRepository<Agent, Long> {

    Optional<Agent> findByName(String name);

    Optional<Agent> findByApiKeyHash(String apiKeyHash);

    long countByStatus(AgentStatus status);
}
