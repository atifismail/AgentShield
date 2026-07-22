-- See postgresql/V15__dlp_redaction_tokens.sql for rationale.
CREATE TABLE redaction_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL UNIQUE,
    category VARCHAR(32) NOT NULL,
    encrypted_original LONGTEXT NOT NULL,
    expires_at TIMESTAMP NULL,
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_redaction_tokens_token ON redaction_tokens(token);
