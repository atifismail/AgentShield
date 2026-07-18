-- See postgresql/V4__agent_credential_lifecycle.sql for rationale.

CREATE TABLE agent_credentials (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    agent_id BIGINT NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    token_prefix VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL,
    expires_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    revoked_by VARCHAR(255),
    revoked_at TIMESTAMP NULL,
    CONSTRAINT fk_agent_credentials_agent FOREIGN KEY (agent_id) REFERENCES agents(id)
) ENGINE=InnoDB;

CREATE INDEX idx_agent_credentials_agent_id ON agent_credentials(agent_id);
CREATE INDEX idx_agent_credentials_status ON agent_credentials(status);

ALTER TABLE agents DROP COLUMN api_key_hash;
