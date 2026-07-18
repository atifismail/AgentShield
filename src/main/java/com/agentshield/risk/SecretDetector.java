package com.agentshield.risk;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Deterministic, pattern-based scan for secret-like values in tool responses.
 * Indicators from PROJECT_PLAN.md section 12, extended with confidence/category metadata
 * (improvement_plan.md #9). Matched text is never returned or logged, only the indicator name,
 * category, confidence, and its location, so the secret itself never ends up in an audit record.
 */
@Component
public class SecretDetector {

    private record SecretPattern(String indicator, DetectorCategory category, Confidence confidence,
            Pattern pattern) {
    }

    private static final List<SecretPattern> PATTERNS = List.of(
            new SecretPattern("aws-access-key", DetectorCategory.CREDENTIAL, Confidence.HIGH,
                    Pattern.compile("AKIA[0-9A-Z]{16}")),
            new SecretPattern("github-token-like", DetectorCategory.TOKEN, Confidence.HIGH,
                    Pattern.compile("gh[pousr]_[A-Za-z0-9]{36,}")),
            new SecretPattern("private-key-header", DetectorCategory.PRIVATE_KEY, Confidence.HIGH,
                    Pattern.compile("-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----")),
            new SecretPattern("jwt-like-token", DetectorCategory.TOKEN, Confidence.MEDIUM,
                    Pattern.compile("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")),
            new SecretPattern("password-assignment", DetectorCategory.CREDENTIAL, Confidence.MEDIUM,
                    Pattern.compile("(?i)password\\s*[:=]\\s*\\S+")),
            new SecretPattern("api-key-assignment", DetectorCategory.CREDENTIAL, Confidence.MEDIUM,
                    Pattern.compile("(?i)api[_-]?key\\s*[:=]\\s*\\S+")),
            new SecretPattern("bearer-token", DetectorCategory.TOKEN, Confidence.MEDIUM,
                    Pattern.compile("(?i)bearer\\s+[A-Za-z0-9\\-_.]{8,}")),
            new SecretPattern("db-url-with-credentials", DetectorCategory.DB_CONNECTION_STRING, Confidence.HIGH,
                    Pattern.compile("(?i)[a-z][a-z0-9+.-]*://[^\\s:/@]+:[^\\s:/@]+@[^\\s]+")));

    /**
     * Common placeholder values that trigger the patterns above but aren't real secrets — sample
     * docs, seeded fixtures, "replace me" instructions. Checked against each match's own matched
     * text (never against the whole response), so a real secret elsewhere in the same response is
     * still caught.
     */
    private static final Pattern ALLOWLIST = Pattern.compile(
            "(?i)(changeme|change_me|change-me|xxx+|\\*{4,}|redacted|placeholder|your[_-]?(api[_-]?)?key"
                    + "|example|dummy|sample|fake|<[a-z_-]+>)");

    public DetectionResult scan(String text) {
        if (text == null || text.isBlank()) {
            return DetectionResult.CLEAN;
        }
        List<DetectionMatch> matches = new ArrayList<>();
        for (SecretPattern secretPattern : PATTERNS) {
            Matcher matcher = secretPattern.pattern().matcher(text);
            while (matcher.find()) {
                if (ALLOWLIST.matcher(matcher.group()).find()) {
                    continue;
                }
                int offset = matcher.start();
                matches.add(new DetectionMatch(secretPattern.indicator(), secretPattern.category(),
                        secretPattern.confidence(), offset, lineOf(text, offset)));
                break;
            }
        }
        return matches.isEmpty() ? DetectionResult.CLEAN : new DetectionResult(true, matches);
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
