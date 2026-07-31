package com.agentshield.tool;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class ToolFingerprintServiceTest {

    private final ToolFingerprintService service = new ToolFingerprintService(new ObjectMapper());

    @Test
    void sameSemanticSchemaWithReorderedKeysYieldsTheSameHash() {
        String original = "{\"type\":\"object\",\"properties\":{\"a\":1,\"b\":2}}";
        String reordered = "{\"properties\":{\"b\":2,\"a\":1},\"type\":\"object\"}";

        assertThat(service.hashJson(original)).isEqualTo(service.hashJson(reordered));
    }

    @Test
    void nestedObjectKeyReorderingAlsoYieldsTheSameHash() {
        String original = "{\"outer\":{\"z\":1,\"a\":{\"y\":2,\"x\":3}}}";
        String reordered = "{\"outer\":{\"a\":{\"x\":3,\"y\":2},\"z\":1}}";

        assertThat(service.hashJson(original)).isEqualTo(service.hashJson(reordered));
    }

    @Test
    void incidentalWhitespaceDoesNotChangeTheJsonHash() {
        String compact = "{\"a\":1}";
        String spaced = "{  \"a\" : 1  }";

        assertThat(service.hashJson(compact)).isEqualTo(service.hashJson(spaced));
    }

    @Test
    void arrayElementOrderIsSemanticallySignificantAndChangesTheHash() {
        String first = "{\"steps\":[\"a\",\"b\"]}";
        String reordered = "{\"steps\":[\"b\",\"a\"]}";

        assertThat(service.hashJson(first)).isNotEqualTo(service.hashJson(reordered));
    }

    @Test
    void aRealContentChangeStillProducesADifferentHash() {
        String before = "{\"properties\":{\"a\":1}}";
        String after = "{\"properties\":{\"a\":2}}";

        assertThat(service.hashJson(before)).isNotEqualTo(service.hashJson(after));
    }

    @Test
    void descriptionHashIsInsensitiveToLeadingTrailingAndRepeatedWhitespace() {
        assertThat(service.hashDescription("Reads   rows\nfrom   the table"))
                .isEqualTo(service.hashDescription("  Reads rows from the table  "));
    }

    @Test
    void aDescriptionWordingChangeProducesADifferentHash() {
        assertThat(service.hashDescription("Reads rows from the table"))
                .isNotEqualTo(service.hashDescription("Reads and deletes rows from the table"));
    }

    @Test
    void nullDescriptionOrSchemaMeansNoDataRatherThanAHashOfEmptyText() {
        assertThat(service.hashDescription(null)).isNull();
        assertThat(service.hashJson(null)).isNull();
        assertThat(service.hashJson("")).isNull();
        assertThat(service.hashJson("   ")).isNull();
    }

    @Test
    void invalidJsonIsHashedAsNormalizedTextInsteadOfThrowing() {
        assertThat(service.hashJson("not { valid json")).isNotNull();
        assertThat(service.hashJson("not { valid json")).isEqualTo(service.hashJson("not {  valid   json"));
    }
}
