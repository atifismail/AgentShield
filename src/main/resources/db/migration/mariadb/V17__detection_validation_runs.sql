-- See postgresql/V17__detection_validation_runs.sql for rationale.
CREATE TABLE detection_validation_runs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scenario_code VARCHAR(64) NOT NULL,
    detection_rule_code VARCHAR(64),
    passed BOOLEAN NOT NULL,
    detail VARCHAR(2000),
    triggered_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_detection_validation_runs_scenario ON detection_validation_runs(scenario_code);
CREATE INDEX idx_detection_validation_runs_rule ON detection_validation_runs(detection_rule_code);
