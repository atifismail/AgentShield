package com.agentshield.risk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Deterministic, pattern-based scan for secret-like values in tool responses.
 * Indicators from PROJECT_PLAN.md section 12. Matched text is never returned or logged,
 * only the indicator name, so the secret itself never ends up in an audit record.
 */
@Component
public class SecretDetector {

    private static final Map<String, Pattern> PATTERNS = new LinkedHashMap<>();

    static {
        PATTERNS.put("aws-access-key", Pattern.compile("AKIA[0-9A-Z]{16}"));
        PATTERNS.put("private-key-header", Pattern.compile("-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"));
        PATTERNS.put("jwt-like-token", Pattern.compile("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"));
        PATTERNS.put("password-assignment", Pattern.compile("(?i)password\\s*[:=]\\s*\\S+"));
        PATTERNS.put("api-key-assignment", Pattern.compile("(?i)api[_-]?key\\s*[:=]\\s*\\S+"));
        PATTERNS.put("bearer-token", Pattern.compile("(?i)bearer\\s+[A-Za-z0-9\\-_.]{8,}"));
        PATTERNS.put("db-url-with-credentials", Pattern.compile("(?i)[a-z][a-z0-9+.-]*://[^\\s:/@]+:[^\\s:/@]+@[^\\s]+"));
    }

    public DetectionResult scan(String text) {
        if (text == null || text.isBlank()) {
            return DetectionResult.CLEAN;
        }
        List<String> matches = new ArrayList<>();
        for (Map.Entry<String, Pattern> entry : PATTERNS.entrySet()) {
            if (entry.getValue().matcher(text).find()) {
                matches.add(entry.getKey());
            }
        }
        return matches.isEmpty() ? DetectionResult.CLEAN : new DetectionResult(true, matches);
    }
}
