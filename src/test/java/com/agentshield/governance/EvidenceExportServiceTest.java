package com.agentshield.governance;

import static org.assertj.core.api.Assertions.assertThat;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.common.ActionCategory;
import com.agentshield.common.PolicyDecisionType;
import com.agentshield.common.TokenHasher;
import com.agentshield.gateway.GatewayDtos;
import com.agentshield.governance.EvidenceExportDtos.EvidenceBundle;
import com.agentshield.support.AbstractIntegrationTest;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import java.io.File;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * agentshield_policy_evidence_execution_plan_2026-07-30.md work package 5, "Required tests": JSON
 * schema validation for representative records, SARIF structural validation, known fake secret/
 * token absence, date filters, RBAC, and empty-result handling.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EvidenceExportServiceTest extends AbstractIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private EvidenceExportService evidenceExportService;
    @Autowired
    private AgentRepository agentRepository;
    @Autowired
    private AgentCredentialRepository agentCredentialRepository;
    @Autowired
    private ToolRepository toolRepository;
    @Autowired
    private ObjectMapper objectMapper;

    private static final String KNOWN_FAKE_SECRET = "AKIAKNOWNFAKESECRETVALUE";

    private final TestRestTemplate admin = new TestRestTemplate("admin", "test-only");
    private final TestRestTemplate anon = new TestRestTemplate();

    private JsonSchema loadSchema(String fileName) {
        File file = new File("docs/schemas/" + fileName);
        return JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7).getSchema(file.toURI());
    }

    private Instant[] produceOneOfEverything() {
        Instant from = Instant.now().minus(Duration.ofMinutes(1));

        Tool tool = new Tool();
        tool.setName("evidence-test-tool-" + System.nanoTime());
        tool.setType(ToolType.SAAS);
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        String hash = TokenHasher.sha256Hex("x");
        tool.setApprovedHash(hash);
        tool.setCurrentHash(hash);
        tool.setToolGroup("saas");
        tool = toolRepository.save(tool);

        Agent agent = new Agent();
        agent.setName("evidence-test-agent-" + System.nanoTime());
        agent.setStatus(AgentStatus.ENABLED);
        agent.setAllowedToolGroups("saas");
        agent = agentRepository.save(agent);

        String plaintextToken = "evidence-test-token-" + System.nanoTime();
        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(TokenHasher.sha256Hex(plaintextToken));
        credential.setTokenPrefix(plaintextToken.substring(0, 8));
        credential.setStatus(CredentialStatus.ACTIVE);
        agentCredentialRepository.save(credential);

        // EXTERNAL_TRANSFER always produces an APPROVAL_REQUIRED decision + approval record.
        ObjectNode body = objectMapper.createObjectNode();
        body.put("toolId", tool.getName());
        body.put("action", "export");
        body.put("actionCategory", ActionCategory.EXTERNAL_TRANSFER.name());
        body.put("targetEnvironment", "DEV");
        body.set("input", objectMapper.createObjectNode().put("note", KNOWN_FAKE_SECRET));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + plaintextToken);
        ResponseEntity<GatewayDtos.InvokeResponse> response = new TestRestTemplate().exchange(
                "http://localhost:" + port + "/api/gateway/invoke", HttpMethod.POST, new HttpEntity<>(body, headers),
                GatewayDtos.InvokeResponse.class);
        assertThat(response.getBody().decision()).isEqualTo(PolicyDecisionType.APPROVAL_REQUIRED);

        Instant to = Instant.now().plus(Duration.ofMinutes(1));
        return new Instant[] {from, to};
    }

    @Test
    void jsonEvidenceBundleValidatesAgainstItsPublishedSchemas() throws Exception {
        Instant[] range = produceOneOfEverything();
        EvidenceBundle bundle = evidenceExportService.generate(range[0], range[1]);
        JsonNode bundleNode = objectMapper.valueToTree(bundle);

        assertThat(loadSchema("evidence-bundle-v1.json").validate(bundleNode)).isEmpty();
        assertThat(bundle.toolCallEvents()).isNotEmpty();
        assertThat(bundle.policyDecisionEvents()).isNotEmpty();
        assertThat(bundle.approvalEvents()).isNotEmpty();

        JsonSchema toolCallSchema = loadSchema("tool-call-event-v1.json");
        for (var event : bundle.toolCallEvents()) {
            assertThat(toolCallSchema.validate(objectMapper.valueToTree(event))).isEmpty();
        }
        JsonSchema decisionSchema = loadSchema("policy-decision-event-v1.json");
        for (var event : bundle.policyDecisionEvents()) {
            assertThat(decisionSchema.validate(objectMapper.valueToTree(event))).isEmpty();
        }
        JsonSchema approvalSchema = loadSchema("approval-event-v1.json");
        for (var event : bundle.approvalEvents()) {
            assertThat(approvalSchema.validate(objectMapper.valueToTree(event))).isEmpty();
        }
    }

    @Test
    void knownFakeSecretNeverAppearsInTheJsonOrSarifExport() {
        Instant[] range = produceOneOfEverything();
        EvidenceBundle bundle = evidenceExportService.generate(range[0], range[1]);
        String json = objectMapper.valueToTree(bundle).toString();
        String sarif = evidenceExportService.toSarif(bundle);

        assertThat(json).doesNotContain(KNOWN_FAKE_SECRET);
        assertThat(sarif).doesNotContain(KNOWN_FAKE_SECRET);
    }

    @Test
    void sarifExportValidatesStructurallyAndContainsOnlyMappedFindings() throws Exception {
        Instant[] range = produceOneOfEverything();
        EvidenceBundle bundle = evidenceExportService.generate(range[0], range[1]);
        String sarif = evidenceExportService.toSarif(bundle);
        JsonNode sarifNode = objectMapper.readTree(sarif);

        assertThat(loadSchema("sarif-subset-v1.json").validate(sarifNode)).isEmpty();

        JsonNode results = sarifNode.at("/runs/0/results");
        assertThat(results.isArray()).isTrue();
        for (JsonNode result : results) {
            assertThat(result.path("ruleId").asText()).isNotBlank();
            assertThat(result.path("locations").isArray()).isTrue();
        }
        // Every result's ruleId must be declared in the tool driver's rules array.
        Set<String> declaredRules = new java.util.HashSet<>();
        sarifNode.at("/runs/0/tool/driver/rules").forEach(r -> declaredRules.add(r.path("id").asText()));
        for (JsonNode result : results) {
            assertThat(declaredRules).contains(result.path("ruleId").asText());
        }
    }

    @Test
    void emptyRangeProducesAnEmptyBundleRatherThanAnError() {
        Instant from = Instant.now().minus(Duration.ofDays(3650));
        Instant to = Instant.now().minus(Duration.ofDays(3649));

        EvidenceBundle bundle = evidenceExportService.generate(from, to);

        assertThat(bundle.toolCallEvents()).isEmpty();
        assertThat(bundle.policyDecisionEvents()).isEmpty();
        assertThat(bundle.approvalEvents()).isEmpty();
        assertThat(bundle.evaluationRunSummaries()).isEmpty();
    }

    @Test
    void adminCanReadTheEvidenceEndpointInBothFormats() {
        Instant now = Instant.now();
        String url = "http://localhost:" + port + "/api/governance/evidence?from=" + now.minusSeconds(60)
                + "&to=" + now.plusSeconds(60);

        ResponseEntity<String> jsonResponse = admin.getForEntity(url + "&format=json", String.class);
        assertThat(jsonResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(jsonResponse.getBody()).contains("\"schemaVersion\":\"evidence-bundle-v1\"");

        ResponseEntity<String> sarifResponse = admin.getForEntity(url + "&format=sarif", String.class);
        assertThat(sarifResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(sarifResponse.getBody()).contains("\"version\":\"2.1.0\"");
    }

    @Test
    void anonymousCannotReadTheEvidenceEndpoint() {
        Instant[] range = produceOneOfEverything();
        String url = "http://localhost:" + port + "/api/governance/evidence?from=" + range[0] + "&to=" + range[1];

        // Anonymous requests get redirected to the login page (form-login entry point) rather
        // than a bare 401/403 — matching this codebase's established convention (e.g.
        // SecurityConfigIntegrationTest). What actually matters is that the evidence data never
        // reaches an unauthenticated caller.
        ResponseEntity<String> response = anon.getForEntity(url, String.class);

        assertThat(response.getBody()).doesNotContain("evidence-bundle-v1");
    }
}
