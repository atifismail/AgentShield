package com.agentshield.mcp;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface McpServerRepository extends JpaRepository<McpServer, Long> {

    Optional<McpServer> findByName(String name);
}
