package com.agentshield.common;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Minimal IPv4 CIDR range matcher — no external dependency needed for the fixed range list this uses. */
public final class CidrMatcher {

    private final byte[] networkBytes;
    private final int prefixLength;

    private CidrMatcher(byte[] networkBytes, int prefixLength) {
        this.networkBytes = networkBytes;
        this.prefixLength = prefixLength;
    }

    public static CidrMatcher parse(String cidr) {
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("not a CIDR range: " + cidr);
        }
        try {
            byte[] address = InetAddress.getByName(parts[0]).getAddress();
            int prefix = Integer.parseInt(parts[1]);
            return new CidrMatcher(address, prefix);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("invalid CIDR range: " + cidr, e);
        }
    }

    public boolean matches(InetAddress address) {
        byte[] candidate = address.getAddress();
        if (candidate.length != networkBytes.length) {
            return false;
        }
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (candidate[i] != networkBytes[i]) {
                return false;
            }
        }
        if (remainingBits == 0) {
            return true;
        }
        int mask = 0xFF << (8 - remainingBits);
        return (candidate[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }
}
