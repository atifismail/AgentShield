package com.agentshield.demo;

import com.agentshield.agent.Agent;
import com.agentshield.agent.AgentCredential;
import com.agentshield.agent.AgentCredentialRepository;
import com.agentshield.agent.AgentRepository;
import com.agentshield.agent.AgentStatus;
import com.agentshield.agent.CredentialStatus;
import com.agentshield.tool.Tool;
import com.agentshield.tool.ToolApprovalStatus;
import com.agentshield.tool.ToolRepository;
import com.agentshield.tool.ToolType;
import java.time.Instant;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds demo agents, tools, and agent credentials idempotently, only when the "demo" Spring
 * profile is active (improvement_plan.md #5). The default-policy baseline row is NOT demo-only
 * — it stays a regular Flyway migration (db/migration/*&#47;V2__seed_demo_data.sql) since every
 * deployment needs it, demo or not.
 *
 * Credential hashes are SHA-256 digests of documented plaintext demo bearer tokens
 * (see docs/demo-lab.md):
 *   coding-agent-01       -&gt; demo-token-coding-agent-01
 *   support-assistant-01  -&gt; demo-token-support-assistant-01
 *   retired-agent-01      -&gt; demo-token-retired-agent-01 (agent is DISABLED, token intentionally inert)
 */
@Component
@Profile("demo")
public class DemoDataSeeder implements ApplicationRunner {

    private final AgentRepository agentRepository;
    private final AgentCredentialRepository credentialRepository;
    private final ToolRepository toolRepository;

    public DemoDataSeeder(AgentRepository agentRepository, AgentCredentialRepository credentialRepository,
            ToolRepository toolRepository) {
        this.agentRepository = agentRepository;
        this.credentialRepository = credentialRepository;
        this.toolRepository = toolRepository;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedAgent("coding-agent-01", "Internal developer coding agent with filesystem, git, and database access",
                "platform-team", AgentStatus.ENABLED, "DEV",
                "c5b68e48db1b3790dd17025b34c1effd475248b65c7f0103766879aa47baa135",
                "source-control,filesystem,database");
        seedAgent("support-assistant-01", "Enterprise assistant connected to SaaS support tools", "support-team",
                AgentStatus.ENABLED, "PROD", "4cc23ab953a8244a26dacf96f81db935189f68eab2caa734b4bb2409a06d8b7d",
                "saas");
        seedAgent("retired-agent-01", "Decommissioned agent kept for audit history", "platform-team",
                AgentStatus.DISABLED, "DEV", "1490fb6c324df67e6db1200489f80555be3a99e4fdc15bf74bb5edeb2a88aa5f",
                "filesystem");

        seedTool("mock-git", ToolType.GIT, "source-control", "/demo/tools/git", "platform-team", "DEV",
                "Mock Git tool for commit and push actions", "{\"actions\":[\"commit\",\"push\",\"createBranch\"]}",
                "seed-hash-git-v1");
        seedTool("mock-database", ToolType.DATABASE, "database", "/demo/tools/database", "platform-team", "PROD",
                "Mock relational database tool for read/write/delete actions",
                "{\"actions\":[\"query\",\"insert\",\"deleteRecords\"]}", "seed-hash-db-v1");
        seedTool("mock-filesystem", ToolType.FILESYSTEM, "filesystem", "/demo/tools/filesystem", "platform-team",
                "DEV", "Mock filesystem tool for read/write file actions",
                "{\"actions\":[\"readFile\",\"writeFile\",\"deleteFile\"]}", "seed-hash-fs-v1");
        seedTool("mock-saas-crm", ToolType.SAAS, "saas", "/demo/tools/saas", "support-team", "PROD",
                "Mock SaaS CRM tool for customer record actions",
                "{\"actions\":[\"getRecord\",\"updateRecord\",\"exportRecords\"]}", "seed-hash-saas-v1");
    }

    private void seedAgent(String name, String description, String owner, AgentStatus status, String environment,
            String tokenHash, String allowedToolGroups) {
        Agent agent = agentRepository.findByName(name).orElse(null);
        if (agent == null) {
            agent = new Agent();
            agent.setName(name);
            agent.setDescription(description);
            agent.setOwner(owner);
            agent.setStatus(status);
            agent.setEnvironment(environment);
            agent.setAllowedToolGroups(allowedToolGroups);
            agent = agentRepository.save(agent);
        }
        if (credentialRepository.findByTokenHash(tokenHash).isPresent()) {
            return;
        }
        AgentCredential credential = new AgentCredential();
        credential.setAgent(agent);
        credential.setTokenHash(tokenHash);
        credential.setTokenPrefix("demo-tok");
        credential.setStatus(CredentialStatus.ACTIVE);
        credential.setCreatedBy("system");
        credentialRepository.save(credential);
    }

    private void seedTool(String name, ToolType type, String toolGroup, String endpointUrl, String owner,
            String environment, String description, String schemaJson, String hash) {
        if (toolRepository.findByName(name).isPresent()) {
            return;
        }
        Tool tool = new Tool();
        tool.setName(name);
        tool.setType(type);
        tool.setToolGroup(toolGroup);
        tool.setEndpointUrl(endpointUrl);
        tool.setOwner(owner);
        tool.setEnvironment(environment);
        tool.setDescription(description);
        tool.setSchemaJson(schemaJson);
        tool.setApprovedHash(hash);
        tool.setCurrentHash(hash);
        tool.setApprovalStatus(ToolApprovalStatus.APPROVED);
        tool.setSourceType(com.agentshield.tool.ToolSourceType.BUILT_IN);
        tool.setLastSeenAt(Instant.now());
        toolRepository.save(tool);
    }
}
