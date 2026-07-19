-- See postgresql/V10__mcp_authorization.sql for rationale.
ALTER TABLE mcp_servers ADD COLUMN auth_mode VARCHAR(32) NOT NULL DEFAULT 'NONE';
ALTER TABLE mcp_servers ADD COLUMN oauth_issuer VARCHAR(1024);
ALTER TABLE mcp_servers ADD COLUMN oauth_resource VARCHAR(1024);
ALTER TABLE mcp_servers ADD COLUMN oauth_token_endpoint VARCHAR(1024);
ALTER TABLE mcp_servers ADD COLUMN oauth_client_id VARCHAR(512);
ALTER TABLE mcp_servers ADD COLUMN oauth_client_secret_ref VARCHAR(512);
ALTER TABLE mcp_servers ADD COLUMN oauth_scopes VARCHAR(1024);

CREATE TABLE mcp_consents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    agent_id BIGINT NOT NULL,
    mcp_server_id BIGINT NOT NULL,
    tool_name VARCHAR(255),
    action_category VARCHAR(32),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    granted_by VARCHAR(255) NOT NULL,
    granted_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NULL,
    revoked_by VARCHAR(255),
    revoked_at TIMESTAMP NULL,
    CONSTRAINT fk_mcp_consents_agent FOREIGN KEY (agent_id) REFERENCES agents(id),
    CONSTRAINT fk_mcp_consents_server FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id)
) ENGINE=InnoDB;

CREATE INDEX idx_mcp_consents_agent_server ON mcp_consents(agent_id, mcp_server_id);

CREATE TABLE mcp_oauth_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    mcp_server_id BIGINT NOT NULL UNIQUE,
    access_token_encrypted LONGTEXT NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    scope VARCHAR(1024),
    CONSTRAINT fk_mcp_oauth_tokens_server FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id)
) ENGINE=InnoDB;
