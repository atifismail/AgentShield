package com.agentshield.dlp;

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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Only created when reversible tokenization is explicitly enabled
 * (see {@link TokenizationEncryptor}, mirroring {@code agentshield.audit.retain-raw-tool-responses}'s
 * gating) — otherwise {@link RedactionService} issues an irreversible {@code [REDACTED:CATEGORY]}
 * placeholder and no row is written here at all.
 */
@Entity
@Table(name = "redaction_tokens")
@Getter
@Setter
@NoArgsConstructor
public class RedactionToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String token;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private DetectorCategory category;

    /** AES-GCM ciphertext, base64 — see {@link TokenizationEncryptor}. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "encrypted_original", nullable = false)
    private String encryptedOriginal;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
