package com.agentshield.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class CidrMatcherTest {

    @Test
    void matchesAddressesInsideRange() throws Exception {
        CidrMatcher matcher = CidrMatcher.parse("169.254.0.0/16");
        assertThat(matcher.matches(InetAddress.getByName("169.254.169.254"))).isTrue();
        assertThat(matcher.matches(InetAddress.getByName("169.254.0.1"))).isTrue();
    }

    @Test
    void doesNotMatchAddressesOutsideRange() throws Exception {
        CidrMatcher matcher = CidrMatcher.parse("169.254.0.0/16");
        assertThat(matcher.matches(InetAddress.getByName("8.8.8.8"))).isFalse();
        assertThat(matcher.matches(InetAddress.getByName("169.253.255.255"))).isFalse();
    }

    @Test
    void matchesPrivateTenSlashEight() throws Exception {
        CidrMatcher matcher = CidrMatcher.parse("10.0.0.0/8");
        assertThat(matcher.matches(InetAddress.getByName("10.1.2.3"))).isTrue();
        assertThat(matcher.matches(InetAddress.getByName("11.0.0.0"))).isFalse();
    }

    @Test
    void matchesNonByteAlignedPrefix() throws Exception {
        CidrMatcher matcher = CidrMatcher.parse("172.16.0.0/12");
        assertThat(matcher.matches(InetAddress.getByName("172.16.0.1"))).isTrue();
        assertThat(matcher.matches(InetAddress.getByName("172.31.255.255"))).isTrue();
        assertThat(matcher.matches(InetAddress.getByName("172.32.0.0"))).isFalse();
    }
}
