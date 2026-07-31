-- See postgresql/V21__agent_tool_grants.sql for rationale.
CREATE TABLE agent_tool_grants (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    agent_id BIGINT NOT NULL,
    tool_id BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    action_category VARCHAR(32),
    target_environment VARCHAR(64),
    resource_path_pattern VARCHAR(512),
    required_token_scope VARCHAR(256),
    not_before TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    created_by VARCHAR(255),
    revoked_by VARCHAR(255),
    revoked_at TIMESTAMP NULL,
    reason VARCHAR(2000),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_agent_tool_grants_agent FOREIGN KEY (agent_id) REFERENCES agents(id),
    CONSTRAINT fk_agent_tool_grants_tool FOREIGN KEY (tool_id) REFERENCES tools(id)
) ENGINE=InnoDB;

CREATE INDEX idx_agent_tool_grants_lookup ON agent_tool_grants(agent_id, tool_id, status);
