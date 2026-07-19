package com.agentshield.tool;

import com.agentshield.audit.AuditService;
import com.agentshield.common.ActorType;
import com.agentshield.common.AuditSeverity;
import com.agentshield.common.ConflictException;
import com.agentshield.common.ResourceNotFoundException;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Owns the {@link ToolProvenance} lifecycle: automatic Level-1 checksum recording on every new
 * {@link ToolVersion}, operator-submitted Level-2 signature verification, revocation, and the
 * approval-time trust-policy gate (design-tool-supply-chain-provenance.md).
 *
 * {@link #verifySignature} and {@link #revoke} always load their own {@code Tool}/{@code
 * ToolVersion} entities by id, rather than accepting them as parameters — both mutate the
 * {@code Tool} row, and an entity handed in by a caller outside this method's own transaction
 * would be detached, so the mutation would silently never be flushed. Loading it here guarantees
 * it's managed by this method's own persistence context.
 */
@Service
public class ToolProvenanceService {

    private final ToolProvenanceRepository provenanceRepository;
    private final ToolRepository toolRepository;
    private final ToolVersionRepository versionRepository;
    private final SignatureVerifier signatureVerifier;
    private final ProvenanceProperties properties;
    private final AuditService auditService;

    public ToolProvenanceService(ToolProvenanceRepository provenanceRepository, ToolRepository toolRepository,
            ToolVersionRepository versionRepository, SignatureVerifier signatureVerifier,
            ProvenanceProperties properties, AuditService auditService) {
        this.provenanceRepository = provenanceRepository;
        this.toolRepository = toolRepository;
        this.versionRepository = versionRepository;
        this.signatureVerifier = signatureVerifier;
        this.properties = properties;
        this.auditService = auditService;
    }

    /**
     * Called whenever {@code ToolService} creates a new {@link ToolVersion} (registration,
     * MCP discovery, or drift) — records the same fingerprint hash already computed for drift
     * detection as this version's Level-1 checksum. Every version gets a row (Level 1 is
     * unconditional, unlike Level 2, which is opt-in) so {@code ToolProvenanceRepository}
     * queries don't need to special-case "no row yet." Called from within the caller's own
     * transaction (e.g. {@code ToolService.register}), so the {@code version} passed in is
     * already managed there — no detached-entity risk here, unlike {@link #verifySignature}.
     */
    @Transactional
    public ToolProvenance recordChecksum(ToolVersion version) {
        ToolProvenance provenance = new ToolProvenance();
        provenance.setToolVersion(version);
        provenance.setChecksumAlgorithm("SHA-256");
        provenance.setChecksum(version.getHash());
        provenance.setVerificationMode(VerificationMode.UNVERIFIED);
        provenance.setVerifiedAt(Instant.now());
        provenance.setVerifiedBy("system");
        provenance.setVerificationDetails("checksum recorded at fingerprint time");
        return provenanceRepository.save(provenance);
    }

    /**
     * Submits a {@code cosign sign-blob --bundle} artifact for the tool's latest version,
     * verified against the given expected Sigstore keyless identity/issuer (design §5). The
     * "artifact" that was signed is the same schema+description content already used for
     * fingerprinting — this is a supply-chain claim about the exact content approval would
     * otherwise trust implicitly. The digest is derived from {@link ToolVersion#getHash()}
     * itself (already the SHA-256 hex of that exact content, per {@code ToolService.fingerprint})
     * rather than recomputed here, so there's no risk of the two ever disagreeing on byte order.
     */
    @Transactional
    public ToolProvenance verifySignature(Long toolId, String bundleJson, String expectedIdentity,
            String expectedIssuer, String verifiedBy) {
        Tool tool = toolRepository.findById(toolId)
                .orElseThrow(() -> new ResourceNotFoundException("tool " + toolId + " not found"));
        ToolVersion latestVersion = versionRepository.findByToolIdOrderByDetectedAtDesc(toolId).stream().findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("tool " + toolId + " has no versions"));
        ToolProvenance provenance = provenanceRepository.findByToolVersionId(latestVersion.getId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "no provenance record for tool version " + latestVersion.getId()));

        byte[] digest = hexToBytes(latestVersion.getHash());
        var result = signatureVerifier.verify(digest, bundleJson, expectedIdentity, expectedIssuer);

        provenance.setSignatureBundle(bundleJson);
        provenance.setVerifiedAt(Instant.now());
        provenance.setVerifiedBy(verifiedBy);
        provenance.setVerificationDetails(result.details());

        if (result.verified()) {
            provenance.setVerificationMode(VerificationMode.SIGNATURE_VERIFIED);
            provenance.setCertificateIdentity(result.certificateIdentity());
            provenance.setCertificateIssuer(result.certificateIssuer());
            auditService.record(null, "tool.provenance_verified", ActorType.USER, verifiedBy, null, tool.getId(),
                    AuditSeverity.INFO,
                    "tool '" + tool.getName() + "' signature verified (identity=" + expectedIdentity + ")", null);
        } else {
            provenance.setVerificationMode(VerificationMode.SIGNATURE_FAILED);
            tool.setApprovalStatus(ToolApprovalStatus.DRIFTED);
            tool.touch();
            toolRepository.save(tool);
            auditService.record(null, "tool.provenance_verification_failed", ActorType.USER, verifiedBy, null,
                    tool.getId(), AuditSeverity.CRITICAL,
                    "tool '" + tool.getName() + "' signature verification failed: " + result.details(), null);
        }
        return provenance;
    }

    /**
     * "A compromised tool or skill" (design §8, acceptance criteria): flips the record to
     * REVOKED and forces the tool back to DRIFTED immediately, reusing the existing
     * {@code PolicyEngine} rule 3 enforcement — no new policy rule needed.
     */
    @Transactional
    public ToolProvenance revoke(Long provenanceId, String reason, String revokedBy) {
        ToolProvenance provenance = provenanceRepository.findById(provenanceId)
                .orElseThrow(() -> new ResourceNotFoundException("tool provenance " + provenanceId + " not found"));
        provenance.setVerificationMode(VerificationMode.REVOKED);
        provenance.setVerifiedAt(Instant.now());
        provenance.setVerifiedBy(revokedBy);
        provenance.setVerificationDetails(reason);

        Tool tool = provenance.getToolVersion().getTool();
        tool.setApprovalStatus(ToolApprovalStatus.DRIFTED);
        tool.touch();
        toolRepository.save(tool);

        auditService.record(null, "tool.provenance_revoked", ActorType.USER, revokedBy, null, tool.getId(),
                AuditSeverity.CRITICAL, "tool '" + tool.getName() + "' provenance revoked: " + reason, null);
        return provenance;
    }

    /**
     * The approval-time gate (design §7): a {@link ToolSourceType} in
     * {@code agentshield.provenance.require-signature-for} must reach SIGNATURE_VERIFIED before
     * its tool can be approved. {@code BUILT_IN} is always exempt regardless of policy (design
     * §13) — the bundled demo tools ship as part of AgentShield itself, not a supply-chain input.
     */
    public void requireSignatureIfPolicyMandates(Tool tool, ToolVersion latestVersion) {
        if (!properties.requiresSignature(tool.getSourceType())) {
            return;
        }
        Optional<ToolProvenance> provenance = provenanceRepository.findByToolVersionId(latestVersion.getId());
        boolean verified = provenance.map(p -> p.getVerificationMode() == VerificationMode.SIGNATURE_VERIFIED)
                .orElse(false);
        if (!verified) {
            throw new ConflictException("tool '" + tool.getName() + "' is source type " + tool.getSourceType()
                    + ", which requires a verified signature before approval — submit one via "
                    + "POST /api/tools/" + tool.getId() + "/provenance/verify");
        }
    }

    public Optional<ToolProvenance> latestForTool(Long toolId) {
        return provenanceRepository.findByToolIdOrderByVersionDetectedAtDesc(toolId).stream().findFirst();
    }

    private byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
