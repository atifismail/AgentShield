package com.agentshield.risk;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class PiiDetectorTest {

    private final PiiDetector detector = new PiiDetector();

    @Test
    void matchesEmailAddress() {
        var result = detector.scan("contact jane.doe@customer-corp.com for details");
        assertThat(result.matched()).isTrue();
        assertThat(result.matchedIndicators()).contains("email-address");
        var match = result.matches().stream().filter(m -> m.indicator().equals("email-address")).findFirst().orElseThrow();
        assertThat(match.category()).isEqualTo(DetectorCategory.EMAIL);
        assertThat(match.length()).isGreaterThan(0);
    }

    @Test
    void skipsAllowlistedExampleDomainEmail() {
        var result = detector.scan("sample contact: user@example.com");
        assertThat(result.matchedIndicators()).doesNotContain("email-address");
    }

    @Test
    void matchesPhoneNumberLike() {
        var result = detector.scan("call me at 555-123-4567 tomorrow");
        assertThat(result.matched()).isTrue();
        var match = result.matches().stream().filter(m -> m.indicator().equals("phone-number-like")).findFirst().orElseThrow();
        assertThat(match.category()).isEqualTo(DetectorCategory.PHONE);
    }

    @Test
    void matchesSsnLikePattern() {
        var result = detector.scan("ssn on file: 123-45-6789");
        assertThat(result.matched()).isTrue();
        var match = result.matches().stream().filter(m -> m.indicator().equals("ssn-like")).findFirst().orElseThrow();
        assertThat(match.category()).isEqualTo(DetectorCategory.NATIONAL_ID);
    }

    @Test
    void matchesResidentRegistrationNumberLikePattern() {
        var result = detector.scan("rrn: 900101-1234567");
        assertThat(result.matched()).isTrue();
        assertThat(result.matchedIndicators()).contains("resident-registration-number-like");
    }

    @Test
    void matchesCreditCardLikeNumberOnlyWhenLuhnValid() {
        // 4111111111111111 is the well-known Visa test number and passes Luhn.
        var result = detector.scan("card on file: 4111111111111111");
        assertThat(result.matched()).isTrue();
        var match = result.matches().stream().filter(m -> m.indicator().equals("credit-card-like")).findFirst().orElseThrow();
        assertThat(match.category()).isEqualTo(DetectorCategory.FINANCIAL_ACCOUNT);
        assertThat(match.confidence()).isEqualTo(Confidence.HIGH);
    }

    @Test
    void doesNotMatchDigitRunThatFailsLuhn() {
        var result = detector.scan("order number 1234567890123456");
        assertThat(result.matchedIndicators()).doesNotContain("credit-card-like");
    }

    @Test
    void isCleanOnOrdinaryText() {
        var result = detector.scan("the quarterly report was filed on time");
        assertThat(result.matched()).isFalse();
    }

    @Test
    void matchesCustomPatternWhenSupplied() {
        var result = detector.scan("internal project codename: PROJECT-NIGHTOWL",
                List.of(Pattern.compile("PROJECT-[A-Z]+")));
        assertThat(result.matched()).isTrue();
        var match = result.matches().stream().filter(m -> m.indicator().equals("custom-pattern")).findFirst().orElseThrow();
        assertThat(match.category()).isEqualTo(DetectorCategory.CUSTOM_PATTERN);
    }

    @Test
    void blankTextIsClean() {
        assertThat(detector.scan("").matched()).isFalse();
        assertThat(detector.scan(null).matched()).isFalse();
    }
}
