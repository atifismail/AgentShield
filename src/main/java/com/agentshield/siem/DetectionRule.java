package com.agentshield.siem;

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

/**
 * A named entry in the detection-rule catalog (improvement_plan.md A5) — maps an identifier that
 * already fires today (a {@code PolicyEngine} rule id, a {@code BaselineFinding} code, or a DLP
 * rule id) to a human-readable name/category/MITRE-ATT&amp;CK-adjacent description, seeded by the
 * V16 migration. This is a catalog of existing controls, not new detection logic.
 */
@Entity
@Table(name = "detection_rules")
@Getter
@Setter
@NoArgsConstructor
public class DetectionRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String code;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, length = 64)
    private String category;

    @Column(length = 2000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private DetectionRuleSource source;

    @Column(name = "reference_id", length = 128)
    private String referenceId;

    /**
     * MITRE-maintained technique reference, nullable — populated only where a defensible mapping
     * exists (V19 migration). A classic ATT&amp;CK id (e.g. {@code T1552}) unless prefixed
     * {@code ATLAS:}, which points at a MITRE ATLAS (AI-specific) technique instead, since classic
     * ATT&amp;CK predates LLM-specific TTPs. Left null for rules with no honest single-technique
     * fit — a behavioral-anomaly detection method or a defensive HITL gate isn't itself an
     * attacker technique, so forcing a mapping there would be a weak, invented reference.
     */
    @Column(name = "mitre_attack_id", length = 32)
    private String mitreAttackId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
