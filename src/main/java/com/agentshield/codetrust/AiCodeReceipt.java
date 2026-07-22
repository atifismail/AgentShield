package com.agentshield.codetrust;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A signed, independently-verifiable receipt for one PASSED {@link CodeAssessment}. Signed with
 * a local Ed25519 keypair ({@link ReceiptSigningService}) rather than the Sigstore keyless
 * verifier used elsewhere in this codebase — Sigstore is verify-only here (AgentShield never
 * signs with it), but a code-trust receipt is something AgentShield itself must produce and sign,
 * a different concern.
 */
@Entity
@Table(name = "ai_code_receipts")
@Getter
@Setter
@NoArgsConstructor
public class AiCodeReceipt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(optional = false)
    @JoinColumn(name = "assessment_id", nullable = false, unique = true)
    private CodeAssessment assessment;

    @Column(name = "commit_sha", nullable = false, length = 64)
    private String commitSha;

    @Column(name = "sbom_hash", length = 128)
    private String sbomHash;

    @Column(name = "scan_summary_hash", nullable = false, length = 128)
    private String scanSummaryHash;

    @Column(nullable = false, length = 32)
    private String algorithm;

    @Column(nullable = false, length = 512)
    private String signature;

    @Column(name = "signer_key_id", nullable = false, length = 128)
    private String signerKeyId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
