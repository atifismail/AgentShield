package com.agentshield.dlp;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.risk.Confidence;
import com.agentshield.risk.DetectionMatch;
import com.agentshield.risk.DetectorCategory;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class RedactionServiceTest {

    private final RedactionTokenRepository tokenRepository = Mockito.mock(RedactionTokenRepository.class);

    @Test
    void redactsMatchedSpanWithCategoryPlaceholderWhenTokenizationDisabled() {
        TokenizationEncryptor encryptor = new TokenizationEncryptor(false, "");
        RedactionService service = new RedactionService(encryptor, tokenRepository);

        String text = "password=hunter2-actual-secret end";
        DetectionMatch match = new DetectionMatch("password-assignment", DetectorCategory.CREDENTIAL,
                Confidence.MEDIUM, 0, "password=hunter2-actual-secret".length(), 1);

        String result = service.redact(text, List.of(match));

        assertThat(result).isEqualTo("[REDACTED:CREDENTIAL] end");
        assertThat(result).doesNotContain("hunter2");
        Mockito.verifyNoInteractions(tokenRepository);
    }

    @Test
    void issuesReversibleTokenWhenTokenizationEnabled() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        TokenizationEncryptor encryptor = new TokenizationEncryptor(true, key);
        RedactionService service = new RedactionService(encryptor, tokenRepository);

        String text = "secret: AKIAABCDEFGHIJKLMNOP";
        int offset = text.indexOf("AKIAABCDEFGHIJKLMNOP");
        DetectionMatch match = new DetectionMatch("aws-access-key", DetectorCategory.CREDENTIAL, Confidence.HIGH,
                offset, "AKIAABCDEFGHIJKLMNOP".length(), 1);

        String result = service.redact(text, List.of(match));

        assertThat(result).startsWith("secret: [dlp-tok-");
        assertThat(result).doesNotContain("AKIAABCDEFGHIJKLMNOP");
        Mockito.verify(tokenRepository).save(Mockito.any(RedactionToken.class));
    }

    @Test
    void replacesMultipleMatchesRightToLeftWithoutCorruptingEarlierOffsets() {
        TokenizationEncryptor encryptor = new TokenizationEncryptor(false, "");
        RedactionService service = new RedactionService(encryptor, tokenRepository);

        String text = "first AKIAABCDEFGHIJKLMNOP then jane@doe.com end";
        int firstOffset = text.indexOf("AKIAABCDEFGHIJKLMNOP");
        int secondOffset = text.indexOf("jane@doe.com");
        DetectionMatch aws = new DetectionMatch("aws-access-key", DetectorCategory.CREDENTIAL, Confidence.HIGH,
                firstOffset, "AKIAABCDEFGHIJKLMNOP".length(), 1);
        DetectionMatch email = new DetectionMatch("email-address", DetectorCategory.EMAIL, Confidence.MEDIUM,
                secondOffset, "jane@doe.com".length(), 1);

        String result = service.redact(text, List.of(aws, email));

        assertThat(result).isEqualTo("first [REDACTED:CREDENTIAL] then [REDACTED:EMAIL] end");
    }

    @Test
    void malformedOffsetIsSkippedDefensivelyInsteadOfCorruptingText() {
        TokenizationEncryptor encryptor = new TokenizationEncryptor(false, "");
        RedactionService service = new RedactionService(encryptor, tokenRepository);

        String text = "short";
        DetectionMatch outOfBounds = new DetectionMatch("x", DetectorCategory.CREDENTIAL, Confidence.LOW, 100, 5, 1);

        String result = service.redact(text, List.of(outOfBounds));

        assertThat(result).isEqualTo(text);
    }

    @Test
    void emptyMatchListReturnsTextUnchanged() {
        TokenizationEncryptor encryptor = new TokenizationEncryptor(false, "");
        RedactionService service = new RedactionService(encryptor, tokenRepository);

        assertThat(service.redact("unchanged", List.of())).isEqualTo("unchanged");
    }
}
