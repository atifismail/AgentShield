-- See postgresql/V23__evaluation_corpus.sql for rationale.
CREATE TABLE evaluation_suites (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version INT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    description VARCHAR(2000),
    checksum VARCHAR(128) NOT NULL,
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    UNIQUE KEY uq_evaluation_suites_name_version (name, version)
) ENGINE=InnoDB;

CREATE TABLE evaluation_cases (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    suite_id BIGINT NOT NULL,
    case_key VARCHAR(255) NOT NULL,
    input_fixture_json LONGTEXT NOT NULL,
    expected_decision VARCHAR(32) NOT NULL,
    expected_rule_id VARCHAR(128),
    expect_no_tool_call BOOLEAN NOT NULL DEFAULT TRUE,
    tags VARCHAR(500),
    checksum VARCHAR(128) NOT NULL,
    CONSTRAINT fk_evaluation_cases_suite FOREIGN KEY (suite_id) REFERENCES evaluation_suites(id)
) ENGINE=InnoDB;

CREATE INDEX idx_evaluation_cases_suite_id ON evaluation_cases(suite_id);

CREATE TABLE evaluation_runs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    suite_id BIGINT NOT NULL,
    suite_version INT NOT NULL,
    policy_config_fingerprint VARCHAR(128),
    triggered_by VARCHAR(255),
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NULL,
    total_cases INT NOT NULL DEFAULT 0,
    passed_cases INT NOT NULL DEFAULT 0,
    failed_cases INT NOT NULL DEFAULT 0,
    error_cases INT NOT NULL DEFAULT 0,
    CONSTRAINT fk_evaluation_runs_suite FOREIGN KEY (suite_id) REFERENCES evaluation_suites(id)
) ENGINE=InnoDB;

CREATE INDEX idx_evaluation_runs_suite_id ON evaluation_runs(suite_id);

CREATE TABLE evaluation_results (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    run_id BIGINT NOT NULL,
    case_id BIGINT NOT NULL,
    actual_decision VARCHAR(32),
    actual_rule_id VARCHAR(128),
    result_status VARCHAR(32) NOT NULL,
    redacted_reason VARCHAR(2000),
    duration_millis BIGINT NOT NULL,
    evaluator_version VARCHAR(32) NOT NULL,
    CONSTRAINT fk_evaluation_results_run FOREIGN KEY (run_id) REFERENCES evaluation_runs(id),
    CONSTRAINT fk_evaluation_results_case FOREIGN KEY (case_id) REFERENCES evaluation_cases(id)
) ENGINE=InnoDB;

CREATE INDEX idx_evaluation_results_run_id ON evaluation_results(run_id);
