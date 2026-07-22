-- See postgresql/V18__code_trust.sql for rationale.
CREATE TABLE code_assessments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    repo VARCHAR(512) NOT NULL,
    commit_sha VARCHAR(64) NOT NULL,
    branch VARCHAR(255),
    author VARCHAR(255),
    source VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    requires_rescan BOOLEAN NOT NULL DEFAULT FALSE,
    requested_by VARCHAR(255),
    approved_by VARCHAR(255),
    approved_at TIMESTAMP NULL,
    rejected_by VARCHAR(255),
    rejected_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_code_assessments_repo_branch ON code_assessments(repo, branch);
CREATE INDEX idx_code_assessments_status ON code_assessments(status);

CREATE TABLE code_findings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    assessment_id BIGINT NOT NULL,
    file_path VARCHAR(1024),
    line INT,
    category VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    rule_id VARCHAR(128),
    message VARCHAR(2000),
    status VARCHAR(16) NOT NULL DEFAULT 'OPEN',
    CONSTRAINT fk_code_findings_assessment FOREIGN KEY (assessment_id) REFERENCES code_assessments(id)
) ENGINE=InnoDB;

CREATE INDEX idx_code_findings_assessment_id ON code_findings(assessment_id);

CREATE TABLE ai_code_receipts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    assessment_id BIGINT NOT NULL UNIQUE,
    commit_sha VARCHAR(64) NOT NULL,
    sbom_hash VARCHAR(128),
    scan_summary_hash VARCHAR(128) NOT NULL,
    algorithm VARCHAR(32) NOT NULL,
    signature VARCHAR(512) NOT NULL,
    signer_key_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_ai_code_receipts_assessment FOREIGN KEY (assessment_id) REFERENCES code_assessments(id)
) ENGINE=InnoDB;
