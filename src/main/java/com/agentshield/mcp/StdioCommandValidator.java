package com.agentshield.mcp;

import java.nio.file.Path;
import org.springframework.stereotype.Component;

/**
 * Allowlist check for the executable a STDIO MCP server would spawn
 * (design-stdio-sse-mcp-transport-and-sandboxing.md §5.1). Mirrors
 * {@link com.agentshield.gateway.OutboundEndpointValidator}'s shape: deny-all-unless-allowed,
 * checked at both registration time and again at spawn time (config can change between the two).
 */
@Component
public class StdioCommandValidator {

    private final StdioMcpProperties properties;

    public StdioCommandValidator(StdioMcpProperties properties) {
        this.properties = properties;
    }

    public ValidationResult validate(String command) {
        if (command == null || command.isBlank()) {
            return ValidationResult.deny("command is required for a STDIO transport server");
        }
        String executableName = Path.of(command.trim()).getFileName().toString();

        if (!properties.isAllowWindowsBatchCommands()) {
            String lower = executableName.toLowerCase();
            if (lower.endsWith(".cmd") || lower.endsWith(".bat")) {
                return ValidationResult.deny(
                        "'" + executableName + "' is a Windows batch file; batch-file invocation goes through "
                                + "cmd.exe's own command-line parsing, which reintroduces metacharacter risk plain "
                                + "argv-array execution doesn't have. Point at the underlying interpreter/binary "
                                + "instead, or set agentshield.stdio.allow-windows-batch-commands=true for local "
                                + "development only (never production)");
            }
        }

        boolean allowed = properties.getAllowedCommands().stream().anyMatch(c -> c.equals(executableName));
        if (!allowed) {
            return ValidationResult.deny(
                    "command '" + executableName + "' is not in the agentshield.stdio.allowed-commands allowlist");
        }
        return ValidationResult.allow();
    }

    public record ValidationResult(boolean allowed, String reason) {

        public static ValidationResult allow() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult deny(String reason) {
            return new ValidationResult(false, reason);
        }
    }
}
