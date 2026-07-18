package com.agentshield.gateway;

import com.agentshield.common.CidrMatcher;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Blocks tool registrations/calls that target internal metadata services, loopback/admin
 * services, or private network ranges — SSRF protection for outbound tool forwarding
 * (improvement_plan.md #2). Relative demo-tool paths (same process) skip this entirely.
 */
@Component
public class OutboundEndpointValidator {

    private final OutboundPolicyProperties properties;
    private final List<CidrMatcher> blockedRanges;

    public OutboundEndpointValidator(OutboundPolicyProperties properties) {
        this.properties = properties;
        this.blockedRanges = properties.getBlockedIpRanges().stream().map(CidrMatcher::parse).toList();
    }

    public ValidationResult validate(String endpointUrl) {
        if (endpointUrl == null || endpointUrl.isBlank()) {
            return ValidationResult.deny("endpoint URL is required");
        }
        if (endpointUrl.startsWith("/")) {
            return properties.isAllowRelativeDemoTools()
                    ? ValidationResult.allow()
                    : ValidationResult.deny("relative tool endpoints are disabled by outbound policy");
        }

        URI uri;
        try {
            uri = URI.create(endpointUrl);
        } catch (Exception e) {
            return ValidationResult.deny("'" + endpointUrl + "' is not a valid URL");
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            return ValidationResult.deny("endpoint URL must use http or https");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return ValidationResult.deny("endpoint URL has no host");
        }
        return validateHost(host);
    }

    public ValidationResult validateHost(String host) {
        boolean explicitlyAllowed = properties.getAllowedHosts().stream().anyMatch(h -> h.equalsIgnoreCase(host));
        if (explicitlyAllowed) {
            return ValidationResult.allow();
        }
        if (properties.isDenyAllUnlessAllowed()) {
            return ValidationResult.deny("host '" + host + "' is not in the outbound allowlist");
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            return ValidationResult.deny("could not resolve host '" + host + "'");
        }
        for (InetAddress address : addresses) {
            for (CidrMatcher range : blockedRanges) {
                if (range.matches(address)) {
                    return ValidationResult.deny(
                            "host '" + host + "' resolves to a blocked address range (" + address.getHostAddress() + ")");
                }
            }
        }
        return ValidationResult.allow();
    }

    public record ValidationResult(boolean allowed, String reason) {

        public static ValidationResult allow() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult deny(String reason) {
            return new ValidationResult(false, reason);
        }
    }
}
