package com.agentshield.dlp;

import com.agentshield.risk.Confidence;
import com.agentshield.risk.DetectorCategory;
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
 * A single DLP detector hit, recorded the same way {@code GatewayToolResponse.detectorMatchesJson}
 * already does for response scanning — indicator name, category, confidence, and location only;
 * the matched text itself is never stored (see {@link com.agentshield.risk.DetectionMatch}).
 * {@code correlationId} reuses the gateway's existing trace-id concept
 * ({@code GatewayRequest.correlationId}) rather than a separate identifier, so a DLP finding can
 * be joined back into the same audit timeline as everything else for that request.
 */
@Entity
@Table(name = "dlp_findings")
@Getter
@Setter
@NoArgsConstructor
public class DlpFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "correlation_id", length = 64)
    private String correlationId;

    @Enumerated(EnumType.STRING)
    @Column(name = "content_stage", nullable = false, length = 32)
    private ContentStage contentStage;

    @Column(nullable = false, length = 128)
    private String indicator;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private DetectorCategory category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Confidence confidence;

    @Column(name = "match_offset")
    private int offset;

    @Column(name = "match_length")
    private int length;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_taken", nullable = false, length = 32)
    private DlpAction actionTaken;

    @Column(name = "classification_profile_id")
    private Long classificationProfileId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
