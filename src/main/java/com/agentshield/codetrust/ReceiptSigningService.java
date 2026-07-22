package com.agentshield.codetrust;

import com.agentshield.common.TokenHasher;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Signs and verifies {@link AiCodeReceipt}s with the Ed25519 keypair from
 * {@link ReceiptSigningKeyProvider}. The signed payload is {@code commitSha + "|" + scanSummaryHash}
 * — both fields are stored on the receipt itself, so {@link #verify(AiCodeReceipt)} is a
 * self-contained check: if either field (or the signature) is altered after signing, verification
 * fails, the same tamper-evidence property {@code com.agentshield.audit.AuditHashChain} gives the
 * audit trail, but via an asymmetric signature instead of a hash chain so a third party can verify
 * a receipt from the public key alone, without trusting AgentShield's own database.
 */
@Component
public class ReceiptSigningService {

    private static final String ALGORITHM = "Ed25519";

    private final ReceiptSigningKeyProvider keyProvider;

    public ReceiptSigningService(ReceiptSigningKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public AiCodeReceipt sign(CodeAssessment assessment, List<CodeFinding> findings) {
        String scanSummaryHash = TokenHasher.sha256Hex(canonicalSummary(findings));
        String payload = signedPayload(assessment.getCommitSha(), scanSummaryHash);

        AiCodeReceipt receipt = new AiCodeReceipt();
        receipt.setAssessment(assessment);
        receipt.setCommitSha(assessment.getCommitSha());
        receipt.setScanSummaryHash(scanSummaryHash);
        receipt.setAlgorithm(ALGORITHM);
        receipt.setSignature(Base64.getEncoder().encodeToString(signBytes(payload)));
        receipt.setSignerKeyId(keyProvider.keyId());
        return receipt;
    }

    /**
     * Self-contained verification: recomputes the signed payload from the receipt's own
     * commitSha/scanSummaryHash columns and checks it against the stored signature using the
     * current signing key's public half. Returns false (never throws) for any malformed or
     * tampered input — a receipt either verifies or it doesn't, there is no partial-credit state.
     */
    public boolean verify(AiCodeReceipt receipt) {
        try {
            String payload = signedPayload(receipt.getCommitSha(), receipt.getScanSummaryHash());
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(keyProvider.publicKey());
            verifier.update(payload.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(receipt.getSignature()));
        } catch (Exception e) {
            return false;
        }
    }

    private String signedPayload(String commitSha, String scanSummaryHash) {
        return commitSha + "|" + scanSummaryHash;
    }

    private byte[] signBytes(String payload) {
        try {
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(keyProvider.privateKey());
            signer.update(payload.getBytes(StandardCharsets.UTF_8));
            return signer.sign();
        } catch (Exception e) {
            throw new IllegalStateException("failed to sign code-trust receipt", e);
        }
    }

    /**
     * A deterministic, order-independent text summary of all findings on an assessment — hashed
     * (never signed in full) so the receipt stays small and never carries raw finding messages.
     */
    private String canonicalSummary(List<CodeFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return "no-findings";
        }
        return findings.stream()
                .map(f -> f.getCategory() + ":" + f.getSeverity() + ":" + String.valueOf(f.getRuleId()) + ":"
                        + String.valueOf(f.getFilePath()) + ":" + String.valueOf(f.getLine()))
                .sorted(Comparator.naturalOrder())
                .collect(Collectors.joining(";"));
    }
}
