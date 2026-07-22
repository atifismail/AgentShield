package com.agentshield.dlp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A database-backed DLP rule an operator can add without a code change, mirroring
 * {@link com.agentshield.policy.PolicyOverride}. Which built-in detectors run and what happens
 * on a match (allow/redact/tokenize/block/approval-required) is entirely configured here, not in
 * code — {@link DlpScanService} always consults the lowest-priority enabled profile, falling
 * back to a safe built-in default (all detectors on, BLOCK on any match) when no profile has been
 * configured yet, so DLP protection is active immediately after migration, not only once an
 * operator has set one up.
 */
@Entity
@Table(name = "classification_profiles")
@Getter
@Setter
@NoArgsConstructor
public class ClassificationProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(length = 16)
    private String locale;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "detect_secrets", nullable = false)
    private boolean detectSecrets = true;

    @Column(name = "detect_pii", nullable = false)
    private boolean detectPii = true;

    @Column(name = "detect_prompt_injection", nullable = false)
    private boolean detectPromptInjection = true;

    /** JSON array of operator-supplied regex strings, matched as {@code CUSTOM_PATTERN}. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "custom_patterns_json")
    private String customPatternsJson;

    @Enumerated(EnumType.STRING)
    @Column(name = "default_action", nullable = false, length = 32)
    private DlpAction defaultAction = DlpAction.BLOCK;

    /** Lower runs first when multiple enabled profiles exist. */
    @Column(nullable = false)
    private int priority = 100;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
