-- See postgresql/V22__approval_profiles.sql for rationale.
CREATE TABLE approval_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    priority INT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    name VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(2000),
    agent_id BIGINT,
    tool_id BIGINT,
    tool_group VARCHAR(128),
    action_category VARCHAR(32),
    target_environment VARCHAR(64),
    risk_tier VARCHAR(32),
    target_role VARCHAR(32) NOT NULL,
    expiration_minutes INT,
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_approval_profiles_agent FOREIGN KEY (agent_id) REFERENCES agents(id),
    CONSTRAINT fk_approval_profiles_tool FOREIGN KEY (tool_id) REFERENCES tools(id)
) ENGINE=InnoDB;

CREATE INDEX idx_approval_profiles_priority ON approval_profiles(priority);

ALTER TABLE approval_requests ADD COLUMN approval_profile_id BIGINT;
ALTER TABLE approval_requests ADD COLUMN assigned_role VARCHAR(32);
ALTER TABLE approval_requests ADD CONSTRAINT fk_approval_requests_profile FOREIGN KEY (approval_profile_id) REFERENCES approval_profiles(id);
