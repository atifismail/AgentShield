package com.agentshield.agent;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AgentCredentialRepository extends JpaRepository<AgentCredential, Long> {

    Optional<AgentCredential> findByTokenHash(String tokenHash);

    List<AgentCredential> findByAgentIdOrderByCreatedAtDesc(Long agentId);

    List<AgentCredential> findByStatus(CredentialStatus status);
}
