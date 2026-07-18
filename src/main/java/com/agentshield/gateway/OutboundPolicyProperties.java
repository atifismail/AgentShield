package com.agentshield.gateway;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "agentshield.gateway.outbound")
public class OutboundPolicyProperties {

    /** Relative paths (e.g. "/demo/tools/git") resolve to this same app and skip the SSRF check entirely. */
    private boolean allowRelativeDemoTools = true;

    /** Hostnames explicitly permitted even if they fall inside a blocked IP range below. */
    private List<String> allowedHosts = List.of("localhost", "127.0.0.1");

    /** CIDR ranges a resolved tool endpoint IP may never fall into, unless its host is in allowedHosts. */
    private List<String> blockedIpRanges = List.of(
            "169.254.0.0/16",
            "0.0.0.0/8",
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16"
    );

    /**
     * When true, every absolute-URL host must be in {@link #allowedHosts} — nothing else is
     * reachable regardless of its resolved IP. Off by default (local/demo); set true in
     * production profiles that don't need arbitrary outbound tool hosts.
     */
    private boolean denyAllUnlessAllowed = false;

    public boolean isAllowRelativeDemoTools() {
        return allowRelativeDemoTools;
    }

    public void setAllowRelativeDemoTools(boolean allowRelativeDemoTools) {
        this.allowRelativeDemoTools = allowRelativeDemoTools;
    }

    public List<String> getAllowedHosts() {
        return allowedHosts;
    }

    public void setAllowedHosts(List<String> allowedHosts) {
        this.allowedHosts = allowedHosts;
    }

    public List<String> getBlockedIpRanges() {
        return blockedIpRanges;
    }

    public void setBlockedIpRanges(List<String> blockedIpRanges) {
        this.blockedIpRanges = blockedIpRanges;
    }

    public boolean isDenyAllUnlessAllowed() {
        return denyAllUnlessAllowed;
    }

    public void setDenyAllUnlessAllowed(boolean denyAllUnlessAllowed) {
        this.denyAllUnlessAllowed = denyAllUnlessAllowed;
    }
}
