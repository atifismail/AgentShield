package com.agentshield.approval;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.approval.ApprovalProfileDtos.ApprovalProfileResponse;
import com.agentshield.approval.ApprovalProfileDtos.CreateApprovalProfileRequest;
import com.agentshield.security.UserRole;
import com.agentshield.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApprovalProfileApiSecurityTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");

    @Test
    void adminCanCreateAndDisableAProfile() {
        var request = new CreateApprovalProfileRequest("api-sec-test-" + System.nanoTime(), null, 10, null, null,
                null, null, null, null, UserRole.APPROVER, null);

        ResponseEntity<ApprovalProfileResponse> createResponse = admin.postForEntity(
                "http://localhost:" + port + "/api/approval-profiles", request, ApprovalProfileResponse.class);
        assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        Long id = createResponse.getBody().id();
        ResponseEntity<ApprovalProfileResponse> disableResponse = admin.postForEntity(
                "http://localhost:" + port + "/api/approval-profiles/" + id + "/disable", null,
                ApprovalProfileResponse.class);
        assertThat(disableResponse.getBody().enabled()).isFalse();
    }

    @Test
    void anonymousCannotCreateAProfile() {
        var request = new CreateApprovalProfileRequest("api-sec-anon-" + System.nanoTime(), null, 10, null, null,
                null, null, null, null, UserRole.APPROVER, null);
        TestRestTemplate anon = new TestRestTemplate();

        ResponseEntity<String> response = anon.postForEntity(
                "http://localhost:" + port + "/api/approval-profiles", request, String.class);

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.CREATED);
    }
}
