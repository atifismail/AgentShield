package com.agentshield.mcp;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface McpOAuthTokenRepository extends JpaRepository<McpOAuthToken, Long> {

    Optional<McpOAuthToken> findByMcpServerId(Long mcpServerId);
}
