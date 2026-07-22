package com.agentshield.risk;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Deterministic, pattern-based scan for personally-identifiable and financial-account-like
 * values, following the same style as {@link SecretDetector}: no ML/embedding model, matched
 * text never leaves the detector, only the indicator name, category, confidence, and location.
 * Backs the DLP scanning path in {@code com.agentshield.dlp} — unlike {@link SecretDetector} and
 * {@link PromptInjectionDetector}, callers may also supply operator-configured custom regexes
 * (from a {@code ClassificationProfile}) via {@link #scan(String, List)}.
 */
@Component
public class PiiDetector {

    private record PiiPattern(String indicator, DetectorCategory category, Confidence confidence, Pattern pattern) {
    }

    private static final List<PiiPattern> PATTERNS = List.of(
            new PiiPattern("email-address", DetectorCategory.EMAIL, Confidence.MEDIUM,
                    Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")),
            new PiiPattern("phone-number-like", DetectorCategory.PHONE, Confidence.LOW,
                    Pattern.compile("(?<!\\d)(\\+?\\d{1,3}[ .-]?)?\\(?\\d{3}\\)?[ .-]\\d{3}[ .-]\\d{4}(?!\\d)")),
            new PiiPattern("ssn-like", DetectorCategory.NATIONAL_ID, Confidence.MEDIUM,
                    Pattern.compile("(?<!\\d)\\d{3}-\\d{2}-\\d{4}(?!\\d)")),
            new PiiPattern("resident-registration-number-like", DetectorCategory.NATIONAL_ID, Confidence.MEDIUM,
                    Pattern.compile("(?<!\\d)\\d{6}-[1-4]\\d{6}(?!\\d)")));

    /**
     * Common non-personal values that would otherwise trip the patterns above — RFC 2606/5737-style
     * documentation domains and well-known payment-network test numbers. Checked against each
     * match's own text, same discipline as {@link SecretDetector#ALLOWLIST}.
     */
    private static final Pattern EMAIL_ALLOWLIST = Pattern.compile(
            "(?i)@(example|test|invalid|localhost)(\\.[a-z]+)?$");

    public DetectionResult scan(String text) {
        return scan(text, List.of());
    }

    /**
     * @param customPatterns operator-configured regexes from a {@code ClassificationProfile},
     *                       matched as {@link DetectorCategory#CUSTOM_PATTERN} in addition to the
     *                       built-in patterns above.
     */
    public DetectionResult scan(String text, List<Pattern> customPatterns) {
        if (text == null || text.isBlank()) {
            return DetectionResult.CLEAN;
        }
        List<DetectionMatch> matches = new ArrayList<>();
        for (PiiPattern piiPattern : PATTERNS) {
            Matcher matcher = piiPattern.pattern().matcher(text);
            while (matcher.find()) {
                if (piiPattern.category() == DetectorCategory.EMAIL
                        && EMAIL_ALLOWLIST.matcher(matcher.group()).find()) {
                    continue;
                }
                int offset = matcher.start();
                matches.add(new DetectionMatch(piiPattern.indicator(), piiPattern.category(), piiPattern.confidence(),
                        offset, matcher.end() - offset, lineOf(text, offset)));
                break;
            }
        }
        matches.addAll(scanCreditCardLike(text));
        if (customPatterns != null) {
            for (Pattern custom : customPatterns) {
                Matcher matcher = custom.matcher(text);
                if (matcher.find()) {
                    int offset = matcher.start();
                    matches.add(new DetectionMatch("custom-pattern", DetectorCategory.CUSTOM_PATTERN, Confidence.MEDIUM,
                            offset, matcher.end() - offset, lineOf(text, offset)));
                }
            }
        }
        return matches.isEmpty() ? DetectionResult.CLEAN : new DetectionResult(true, matches);
    }

    /**
     * 13-19 digit runs (optionally grouped with spaces/dashes) that pass a Luhn checksum —
     * catching a bare digit run without a checksum check would be almost pure noise (phone
     * numbers, order IDs, timestamps all match), so this is the one built-in pattern gated by a
     * validity check rather than an allowlist.
     */
    private List<DetectionMatch> scanCreditCardLike(String text) {
        Matcher matcher = Pattern.compile("(?<!\\d)(?:\\d[ -]?){13,19}(?!\\d)").matcher(text);
        List<DetectionMatch> matches = new ArrayList<>();
        while (matcher.find()) {
            String digitsOnly = matcher.group().replaceAll("[ -]", "");
            if (digitsOnly.length() >= 13 && digitsOnly.length() <= 19 && passesLuhn(digitsOnly)) {
                int offset = matcher.start();
                matches.add(new DetectionMatch("credit-card-like", DetectorCategory.FINANCIAL_ACCOUNT, Confidence.HIGH,
                        offset, matcher.end() - offset, lineOf(text, offset)));
            }
        }
        return matches;
    }

    private boolean passesLuhn(String digits) {
        int sum = 0;
        boolean alternate = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = digits.charAt(i) - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) {
                    n -= 9;
                }
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    private static int lineOf(String text, int offset) {
        int line = 1;
        for (int i = 0; i < offset; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }
}
