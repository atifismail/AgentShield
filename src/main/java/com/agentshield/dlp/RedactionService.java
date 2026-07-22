package com.agentshield.dlp;

import com.agentshield.risk.DetectionMatch;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Replaces each matched span in a piece of text with either an irreversible
 * {@code [REDACTED:<category>]} placeholder (default) or, when reversible tokenization is
 * explicitly enabled, an opaque token that can later be resolved back to the original value.
 * Operates directly on the raw text the caller already holds (the same text passed into the
 * detector's {@code scan(...)}) — this is not a violation of the detectors' "matched text never
 * leaves the detector" discipline, since the substring is derived here from text the caller
 * already has, not returned by the detector itself.
 */
@Component
public class RedactionService {

    private final TokenizationEncryptor tokenizationEncryptor;
    private final RedactionTokenRepository redactionTokenRepository;

    public RedactionService(TokenizationEncryptor tokenizationEncryptor,
            RedactionTokenRepository redactionTokenRepository) {
        this.tokenizationEncryptor = tokenizationEncryptor;
        this.redactionTokenRepository = redactionTokenRepository;
    }

    @Transactional
    public String redact(String text, List<DetectionMatch> matches) {
        if (text == null || matches == null || matches.isEmpty()) {
            return text;
        }
        // Replace right-to-left so an earlier match's offset is never invalidated by a later
        // replacement changing the string's length.
        List<DetectionMatch> byOffsetDesc = matches.stream()
                .sorted(Comparator.comparingInt(DetectionMatch::offset).reversed())
                .toList();
        StringBuilder result = new StringBuilder(text);
        for (DetectionMatch match : byOffsetDesc) {
            int start = match.offset();
            int end = start + match.length();
            if (start < 0 || match.length() <= 0 || end > result.length()) {
                continue;
            }
            String original = result.substring(start, end);
            String replacement = tokenizationEncryptor.isEnabled()
                    ? issueToken(original, match)
                    : "[REDACTED:" + match.category().name() + "]";
            result.replace(start, end, replacement);
        }
        return result.toString();
    }

    private String issueToken(String original, DetectionMatch match) {
        String token = "dlp-tok-" + UUID.randomUUID();
        RedactionToken entity = new RedactionToken();
        entity.setToken(token);
        entity.setCategory(match.category());
        entity.setEncryptedOriginal(tokenizationEncryptor.encrypt(original));
        entity.setCreatedAt(Instant.now());
        redactionTokenRepository.save(entity);
        return "[" + token + "]";
    }
}
