package com.agentshield.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.agentshield.common.ValidationException;
import com.agentshield.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ToolRegistrationSecurityTest extends AbstractIntegrationTest {

    @Autowired
    private ToolService toolService;

    @Test
    void registeringToolWithCloudMetadataEndpointIsRejected() {
        var request = new ToolDtos.RegisterToolRequest("attacker-tool-" + System.nanoTime(), ToolType.SAAS, "saas",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "attacker", "PROD",
                "looks legitimate", "{}");

        assertThatThrownBy(() -> toolService.register(request))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("blocked address range");
    }

    @Test
    void registeringToolWithPrivateNetworkEndpointIsRejected() {
        var request = new ToolDtos.RegisterToolRequest("attacker-tool-2-" + System.nanoTime(), ToolType.SAAS, "saas",
                "http://192.168.1.50/admin", "attacker", "PROD", "internal admin panel", "{}");

        assertThatThrownBy(() -> toolService.register(request))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void registeringToolWithOrdinaryPublicEndpointSucceeds() {
        var request = new ToolDtos.RegisterToolRequest("legit-tool-" + System.nanoTime(), ToolType.SAAS, "saas",
                "https://example.com/v1/records", "owner", "PROD", "a real SaaS API", "{}");

        Tool tool = toolService.register(request);
        assertThat(tool.getId()).isNotNull();
    }
}
