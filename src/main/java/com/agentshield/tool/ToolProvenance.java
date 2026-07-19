package com.agentshield.tool;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Supply-chain trust record for one {@link ToolVersion} — one row per version, the same
 * versioning granularity as approval itself (design-tool-supply-chain-provenance.md §4). A
 * {@link ToolVersion} with no {@code ToolProvenance} row is implicitly {@link VerificationMode#UNVERIFIED}
 * — this table is entirely additive, so nothing already deployed is affected until an operator
 * opts a tool's {@link ToolSourceType} into {@code agentshield.provenance.require-signature-for}.
 */
@Entity
@Table(name = "tool_provenance")
@Getter
@Setter
@NoArgsConstructor
public class ToolProvenance {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(optional = false)
    @JoinColumn(name = "tool_version_id", nullable = false, unique = true)
    private ToolVersion toolVersion;

    /** Free-text trusted-publisher/owner metadata — informational, not itself verified. */
    @Column(length = 512)
    private String publisher;

    @Column(name = "checksum_algorithm", length = 32)
    private String checksumAlgorithm;

    @Column(length = 128)
    private String checksum;

    @Enumerated(EnumType.STRING)
    @Column(name = "verification_mode", nullable = false, length = 32)
    private VerificationMode verificationMode = VerificationMode.UNVERIFIED;

    /** The raw Sigstore bundle JSON submitted for verification — stored for audit/re-verification, never a secret. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "signature_bundle")
    private String signatureBundle;

    /** Sigstore keyless: the OIDC identity (email / CI workflow ref) the signing cert was issued to. */
    @Column(name = "certificate_identity", length = 1024)
    private String certificateIdentity;

    /** Sigstore keyless: the OIDC issuer that authenticated the signer. */
    @Column(name = "certificate_issuer", length = 1024)
    private String certificateIssuer;

    /** Key-based verification only: reference to the trusted public key used (never the key material itself). */
    @Column(name = "public_key_ref", length = 512)
    private String publicKeyRef;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    /** "system" for automatic checksum recording, or an operator name for a signature verification/revocation. */
    @Column(name = "verified_by")
    private String verifiedBy;

    @Column(name = "verification_details", length = 2000)
    private String verificationDetails;
}
