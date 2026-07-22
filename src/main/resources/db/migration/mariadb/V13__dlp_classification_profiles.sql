-- See postgresql/V13__dlp_classification_profiles.sql for rationale.
CREATE TABLE classification_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    locale VARCHAR(16),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    detect_secrets BOOLEAN NOT NULL DEFAULT TRUE,
    detect_pii BOOLEAN NOT NULL DEFAULT TRUE,
    detect_prompt_injection BOOLEAN NOT NULL DEFAULT TRUE,
    custom_patterns_json LONGTEXT,
    default_action VARCHAR(32) NOT NULL DEFAULT 'BLOCK',
    priority INT NOT NULL DEFAULT 100,
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_classification_profiles_enabled ON classification_profiles(enabled);
