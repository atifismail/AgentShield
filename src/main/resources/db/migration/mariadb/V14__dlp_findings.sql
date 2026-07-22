-- See postgresql/V14__dlp_findings.sql for rationale.
CREATE TABLE dlp_findings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    correlation_id VARCHAR(64),
    content_stage VARCHAR(32) NOT NULL,
    indicator VARCHAR(128) NOT NULL,
    category VARCHAR(32) NOT NULL,
    confidence VARCHAR(16) NOT NULL,
    match_offset INT,
    match_length INT,
    action_taken VARCHAR(32) NOT NULL,
    classification_profile_id BIGINT,
    created_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_dlp_findings_correlation_id ON dlp_findings(correlation_id);
CREATE INDEX idx_dlp_findings_content_stage ON dlp_findings(content_stage);
CREATE INDEX idx_dlp_findings_category ON dlp_findings(category);
CREATE INDEX idx_dlp_findings_created_at ON dlp_findings(created_at);
