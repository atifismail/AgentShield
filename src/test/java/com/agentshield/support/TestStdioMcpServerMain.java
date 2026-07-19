package com.agentshield.support;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal JSON-RPC-over-stdio fake MCP server for stdio transport tests
 * (design-stdio-sse-mcp-transport-and-sandboxing.md §12) — plain Java, launched via
 * {@code java -cp <test classpath> com.agentshield.support.TestStdioMcpServerMain <mode>} so the
 * whole test suite runs identically on the Windows dev machine and Linux CI without any
 * OS-specific script or shim. Hand-rolled, extremely small JSON parsing/writing rather than
 * pulling in Jackson here — this class runs as a bare subprocess outside the Spring context, and
 * every request this test fixture needs to understand has a fixed, simple shape.
 *
 * Modes:
 * <ul>
 *   <li>{@code echo} (default) — responds normally to tools/list and tools/call.</li>
 *   <li>{@code hang} — never responds; simulates an unresponsive server for the call-timeout test.</li>
 *   <li>{@code oversized-output} — writes a response far larger than any reasonable test
 *       {@code max-output-bytes}, without ever completing the line, for the output-size-limit test.</li>
 *   <li>{@code crash} — responds normally once, then exits non-zero, for the crash/respawn test.</li>
 *   <li>{@code dump-env} — responds with its own full visible environment, for the
 *       environment-isolation test.</li>
 * </ul>
 */
public final class TestStdioMcpServerMain {

    private TestStdioMcpServerMain() {
    }

    public static void main(String[] args) throws IOException {
        String mode = args.length > 0 ? args[0] : "echo";
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);

        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) {
                continue;
            }
            String id = extractId(line);
            String method = extractString(line, "method");

            switch (mode) {
                case "hang" -> {
                    sleepQuietly(120_000);
                    return;
                }
                case "oversized-output" -> {
                    writeRaw(out, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"data\":\"");
                    writeRaw(out, "A".repeat(10_000));
                    writeRaw(out, "\"}}");
                    out.print('\n');
                    out.flush();
                }
                case "crash" -> {
                    writeLine(out, respond(id, method));
                    out.flush();
                    System.exit(1);
                }
                case "dump-env" -> {
                    writeLine(out, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":" + envAsJson() + "}");
                    out.flush();
                }
                default -> {
                    writeLine(out, respond(id, method));
                    out.flush();
                }
            }
        }
    }

    private static String respond(String id, String method) {
        if ("tools/list".equals(method)) {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id
                    + ",\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"Echoes input\",\"inputSchema\":{}}]}}";
        }
        return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"echoed\":true}}";
    }

    private static String envAsJson() {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : new TreeMap<>(System.getenv()).entrySet()) {
            if (!first) {
                json.append(',');
            }
            json.append('"').append(escape(entry.getKey())).append("\":\"").append(escape(entry.getValue())).append('"');
            first = false;
        }
        return json.append('}').toString();
    }

    private static void writeLine(PrintStream out, String content) {
        out.print(content);
        out.print('\n');
    }

    private static void writeRaw(PrintStream out, String content) {
        out.print(content);
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String extractId(String jsonLine) {
        int idx = jsonLine.indexOf("\"id\":");
        if (idx < 0) {
            return "0";
        }
        int start = idx + 5;
        int end = start;
        while (end < jsonLine.length() && Character.isDigit(jsonLine.charAt(end))) {
            end++;
        }
        return end > start ? jsonLine.substring(start, end) : "0";
    }

    private static String extractString(String jsonLine, String field) {
        String marker = "\"" + field + "\":\"";
        int idx = jsonLine.indexOf(marker);
        if (idx < 0) {
            return "";
        }
        int start = idx + marker.length();
        int end = jsonLine.indexOf('"', start);
        return end < 0 ? "" : jsonLine.substring(start, end);
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
