-- See postgresql/V8__gateway_tool_responses.sql for rationale.
CREATE TABLE gateway_tool_responses (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    gateway_request_id BIGINT NOT NULL,
    status_code INT,
    response_body_hash VARCHAR(128),
    response_summary VARCHAR(4000),
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    block_reason VARCHAR(2000),
    detector_matches_json VARCHAR(2000),
    raw_response_encrypted LONGTEXT,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_gateway_tool_responses_request FOREIGN KEY (gateway_request_id) REFERENCES gateway_requests(id)
) ENGINE=InnoDB;

CREATE INDEX idx_gateway_tool_responses_request_id ON gateway_tool_responses(gateway_request_id);
