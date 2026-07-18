-- See postgresql/V7__mcp_servers.sql for rationale.
CREATE TABLE mcp_servers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    transport_type VARCHAR(32) NOT NULL,
    endpoint_url VARCHAR(1024),
    command VARCHAR(1024),
    args VARCHAR(2000),
    env_ref VARCHAR(255),
    owner VARCHAR(255),
    environment VARCHAR(64),
    tool_group VARCHAR(128) NOT NULL DEFAULT 'default',
    discovered_tools_hash VARCHAR(128),
    last_discovered_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

ALTER TABLE tools ADD COLUMN mcp_server_id BIGINT;
ALTER TABLE tools ADD COLUMN mcp_tool_name VARCHAR(255);
ALTER TABLE tools ADD CONSTRAINT fk_tools_mcp_server FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id);
