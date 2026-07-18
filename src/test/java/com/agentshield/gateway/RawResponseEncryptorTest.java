package com.agentshield.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class RawResponseEncryptorTest {

    private static final String VALID_KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    void disabledEncryptorReturnsNullAndNeverRequiresAKey() {
        RawResponseEncryptor encryptor = new RawResponseEncryptor(false, "");

        assertThat(encryptor.isEnabled()).isFalse();
        assertThat(encryptor.encrypt("secret")).isNull();
    }

    @Test
    void enablingWithoutAKeyFailsFastAtStartup() {
        assertThatThrownBy(() -> new RawResponseEncryptor(true, ""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("raw-response-encryption-key");
    }

    @Test
    void enablingWithNonBase64KeyFailsFast() {
        assertThatThrownBy(() -> new RawResponseEncryptor(true, "not-valid-base64!!!"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void enablingWithWrongLengthKeyFailsFast() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);

        assertThatThrownBy(() -> new RawResponseEncryptor(true, shortKey))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void encryptThenDecryptRoundTripsAndNeverStoresPlaintext() {
        RawResponseEncryptor encryptor = new RawResponseEncryptor(true, VALID_KEY);

        String ciphertext = encryptor.encrypt("api_key=super-secret-value");

        assertThat(ciphertext).isNotBlank();
        assertThat(ciphertext).doesNotContain("super-secret-value");
        assertThat(encryptor.decrypt(ciphertext)).isEqualTo("api_key=super-secret-value");
    }

    @Test
    void twoEncryptionsOfTheSamePlaintextProduceDifferentCiphertext() {
        RawResponseEncryptor encryptor = new RawResponseEncryptor(true, VALID_KEY);

        String first = encryptor.encrypt("same-value");
        String second = encryptor.encrypt("same-value");

        assertThat(first).isNotEqualTo(second);
    }
}
