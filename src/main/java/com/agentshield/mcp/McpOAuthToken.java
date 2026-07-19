package com.agentshield.mcp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Cached OAuth 2.1 access token AgentShield obtained for itself to call a given MCP server
 * (design-mcp-authorization.md §4, §6.6). Never exposed via any API, log line, or audit event —
 * only validation outcomes are ever recorded. One row per {@link McpServer}; refreshed in place
 * rather than accumulating history.
 */
@Entity
@Table(name = "mcp_oauth_tokens")
@Getter
@Setter
@NoArgsConstructor
public class McpOAuthToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(optional = false)
    @JoinColumn(name = "mcp_server_id", nullable = false, unique = true)
    private McpServer mcpServer;

    /** AES-256-GCM ciphertext, base64 — see {@link McpTokenEncryptor}. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "access_token_encrypted", nullable = false)
    private String accessTokenEncrypted;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(length = 1024)
    private String scope;
}
