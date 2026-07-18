package com.agentshield.gateway;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Forensic record of a tool response, without storing the raw body by default
 * (improvement_plan.md #7) — see {@code response_summary}'s Javadoc on
 * {@link com.agentshield.gateway.GatewayService} for what it contains in each case.
 */
@Entity
@Table(name = "gateway_tool_responses")
@Getter
@Setter
@NoArgsConstructor
public class GatewayToolResponse {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "gateway_request_id", nullable = false)
    private GatewayRequest gatewayRequest;

    @Column(name = "status_code")
    private Integer statusCode;

    @Column(name = "response_body_hash", length = 128)
    private String responseBodyHash;

    @Column(name = "response_summary", length = 4000)
    private String responseSummary;

    @Column(nullable = false)
    private boolean blocked;

    @Column(name = "block_reason", length = 2000)
    private String blockReason;

    /** JSON array of detector indicator names only (e.g. ["aws-access-key"]) — never matched text. */
    @Column(name = "detector_matches_json", length = 2000)
    private String detectorMatchesJson;

    /** AES-GCM ciphertext, base64. Only present when raw retention is explicitly enabled. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "raw_response_encrypted")
    private String rawResponseEncrypted;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
