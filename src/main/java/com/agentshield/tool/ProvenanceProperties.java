package com.agentshield.tool;

import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Trust policy for supply-chain provenance (design-tool-supply-chain-provenance.md §6). Ships
 * with {@code requireSignatureFor} empty and no trusted identities — Level 2 (signature
 * verification) is entirely opt-in per {@link ToolSourceType}; every tool stays at Level 1
 * (checksum-only, today's behavior) until an operator deliberately configures this.
 */
@Component
@ConfigurationProperties(prefix = "agentshield.provenance")
public class ProvenanceProperties {

    /** Source types that MUST reach SIGNATURE_VERIFIED before a tool can be APPROVED. */
    private Set<ToolSourceType> requireSignatureFor = Set.of();

    private List<TrustedIdentity> trustedIdentities = List.of();

    public Set<ToolSourceType> getRequireSignatureFor() {
        return requireSignatureFor;
    }

    public void setRequireSignatureFor(Set<ToolSourceType> requireSignatureFor) {
        this.requireSignatureFor = requireSignatureFor;
    }

    public List<TrustedIdentity> getTrustedIdentities() {
        return trustedIdentities;
    }

    public void setTrustedIdentities(List<TrustedIdentity> trustedIdentities) {
        this.trustedIdentities = trustedIdentities;
    }

    public boolean requiresSignature(ToolSourceType sourceType) {
        return sourceType != ToolSourceType.BUILT_IN && requireSignatureFor.contains(sourceType);
    }

    /** A Sigstore keyless (identity, issuer) pair an operator has explicitly decided to trust. */
    public static class TrustedIdentity {
        private String identity;
        private String issuer;

        public String getIdentity() {
            return identity;
        }

        public void setIdentity(String identity) {
            this.identity = identity;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }
    }
}
