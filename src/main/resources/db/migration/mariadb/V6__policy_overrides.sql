-- See postgresql/V6__policy_overrides.sql for rationale.
CREATE TABLE policy_overrides (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    action_category VARCHAR(32),
    target_environment VARCHAR(64),
    tool_group VARCHAR(128),
    agent_name VARCHAR(255),
    decision VARCHAR(32) NOT NULL,
    reason VARCHAR(2000) NOT NULL,
    priority INT NOT NULL DEFAULT 100,
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_policy_overrides_enabled ON policy_overrides(enabled);
