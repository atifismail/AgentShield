# Demo Attack Lab

AgentShield ships with four mock tools and seed data so you can see the gateway block real
attack patterns without wiring up any real infrastructure. This requires the `demo` Spring
profile (`docker compose up` enables it by default; for `./gradlew bootRun` set
`SPRING_PROFILES_ACTIVE=demo` — see `docs/deployment.md`). It is intentionally **not** available
in a plain production deployment.

## Mock tools

| Tool (seed name) | Endpoint | Purpose |
|---|---|---|
| `mock-git` | `/demo/tools/git` | Simulates commit/push/branch actions |
| `mock-database` | `/demo/tools/database` | Simulates query/insert/delete; querying the fictional `internal_credentials` table returns secret-like data on purpose |
| `mock-filesystem` | `/demo/tools/filesystem` | Simulates file reads; reading `notes/shared-todo.txt` returns content with a planted prompt-injection attempt on purpose |
| `mock-saas-crm` | `/demo/tools/saas` | Simulates a CRM export action (EXTERNAL_TRANSFER) |

## Demo agents and tokens

Seed data creates three agents, each with one `agent_credentials` row whose `token_hash` is a
SHA-256 digest of these plaintext demo tokens (see `com.agentshield.demo.DemoDataSeeder`):

| Agent | Status | Bearer token |
|---|---|---|
| `coding-agent-01` | ENABLED | `demo-token-coding-agent-01` |
| `support-assistant-01` | ENABLED | `demo-token-support-assistant-01` |
| `retired-agent-01` | DISABLED | `demo-token-retired-agent-01` |

## Running the walkthrough

```bash
./scripts/demo-attack-lab.sh http://localhost:8080
```

Requires `curl` and `jq`. It exercises, in order:

0. **Baseline allowed call** — `coding-agent-01` commits through `mock-git`. Confirms the happy
   path works before anything else.
1. **Tool schema drift is detected and blocked** — the script re-fingerprints `mock-git` with a
   changed schema (via `POST /api/tools/{id}/refresh`), the tool flips to `DRIFTED`, and the next
   call is denied by policy rule `deny-schema-drift`. The script then re-approves the new version
   to restore normal operation.
2. **Production destructive action is denied outright** — a `DESTRUCTIVE` action against `PROD`
   on `mock-database` is denied by policy rule `deny-prod-destructive-without-approval` before it
   ever reaches the tool. Destructive PROD actions have no approval path in this release — see
   `docs/policy-guide.md` for why.
3. **Secret-like response is blocked** — an `EXTERNAL_TRANSFER` query against `mock-database`
   first requires human approval (rule `require-approval-external-transfer`). Once a
   security analyst approves it, the gateway executes the call, the response scanner finds
   secret-like content, and rule `deny-secret-external-transfer` blocks it from reaching the
   agent — an `Incident` is created.
4. **Prompt-injected tool response is blocked** — `coding-agent-01` reads
   `notes/shared-todo.txt` through `mock-filesystem`. This is a plain `READ`, so it's allowed
   pre-call, but the response contains a planted prompt-injection phrase; rule
   `deny-prompt-injection-response` blocks it before it reaches the agent, and an `Incident` is
   created.
5. **External transfer requires human approval** — `support-assistant-01` calls
   `exportRecords` on `mock-saas-crm`. It's queued for approval rather than executed
   automatically, demonstrating the approval gate itself.
6. **Tool misuse is denied** — `support-assistant-01` (allowed only the `saas` tool group) tries
   to push through `mock-git` (`source-control` group); denied by `deny-tool-outside-allowed-group`
   before the tool is ever reached.
7. **Identity and privilege abuse is denied** — `retired-agent-01`'s credential is cryptographically
   valid (correct token hash) but the agent itself is `DISABLED`; denied by `deny-disabled-agent`
   regardless of the credential's validity.
8. **Supply-chain provenance record** — every tool version, including built-in demo tools, gets an
   automatic Level-1 checksum record on discovery/approval; the script reads it back via
   `GET /api/tools/{id}/provenance`.
9. **Unexpected code execution attempt is closed by default** — registering a `STDIO`-transport MCP
   server (local subprocess execution) is rejected outright in this demo deployment because
   `agentshield.stdio.enabled` is not set to `true` — the capability doesn't exist unless an
   operator explicitly turns it on.

After running it, open the **Audit** and **Incidents** pages in the UI (default admin login —
see `docs/operations.md`) to see the full trail each scenario left behind, correlated by request.

## Risk mapping

Each attack scenario demonstrates a control against a specific, named risk category
(`docs/threat-model.md` has the full writeup of each). This table also covers
improvement_plan.md's OWASP Agentic AI attack-scenario checklist explicitly — every category on
that list is mapped to a concrete scenario or test below, not left implicit:

| Scenario | Risk category | Control that blocks/detects it |
|---|---|---|
| 1. Tool schema drift | OWASP Agentic Skills Top 10 — supply-chain compromise / update drift; threat-model §1 Tool poisoning | Fingerprint hash comparison, `deny-schema-drift` policy rule |
| 2. PROD destructive action | OWASP Agentic AI Top 10 — excessive agency; threat-model §2 Excessive agency | `deny-prod-destructive-without-approval` policy rule (no approval path for this category by design) |
| 3. Secret-like response | OWASP LLM Top 10 — sensitive information disclosure; threat-model §4 Prompt and response injection | `SecretDetector` + `deny-secret-external-transfer` policy rule |
| 4. Prompt-injected response | OWASP LLM Top 10 — prompt injection; OWASP Agentic AI Top 10 — **agent goal hijack** / agent behavior hijacking; also demonstrates **memory/context poisoning** (a tool response engineered to alter the agent's downstream behavior, not just this one action) — threat-model §4 | `PromptInjectionDetector` + `deny-prompt-injection-response` policy rule — blocked *before* the content ever reaches the agent's context, so it can't poison anything downstream |
| 5. External transfer approval | OWASP Agentic AI Top 10 — excessive agency (human-in-the-loop); threat-model §2 | `require-approval-external-transfer` policy rule, approval workflow |
| 6. Tool misuse | OWASP Agentic AI Top 10 — **tool misuse** | `deny-tool-outside-allowed-group` policy rule |
| 7. Identity/privilege abuse | OWASP Agentic AI Top 10 — **identity and privilege abuse** | `deny-disabled-agent` policy rule — agent status is checked independently of credential validity |
| 8. Supply-chain provenance | OWASP Agentic Skills Top 10 — **agentic supply-chain vulnerability** | Automatic Level-1 checksum record per tool version, optional Level-2 Sigstore verification (`docs/api.md` "Supply-chain provenance") |
| 9. Stdio disabled by default | OWASP Agentic AI Top 10 — **unexpected code execution attempt** | `agentshield.stdio.enabled=false` by default; command allowlist and sandboxing when enabled (`design-stdio-sse-mcp-transport-and-sandboxing.md`) |
| *(not scripted — see below)* **Resource exhaustion through tool output** | OWASP Agentic AI Top 10 — resource exhaustion | `agentshield.stdio.max-output-bytes` / `agentshield.mcp.sse.max-response-bytes` — a response exceeding the limit aborts the read and closes the connection/process rather than buffering it; proven by `StdioMcpIntegrationTest.outputSizeLimitFailsClosedAndKillsTheProcess` and `McpSseIntegrationTest.oversizedResponseFailsClosed` |
| 10. MCP token misuse *(not scripted here — see below)* | OWASP MCP Top 10 — token mismanagement | OAuth 2.1 audience/issuer/expiry/scope validation, `com.agentshield.mcp.McpOAuthTokenService` — proven by `McpTokenMisuseAttackScenarioTest`, not this script or `AttackSimulatorService` |
| 11. Data leakage through RAG output | OWASP LLM Top 10 — sensitive information disclosure | `DlpScanService` + `deny-dlp-block` — `POST /api/dlp/rag/scan` |
| 12. AI coding assistant introduces a secret | OWASP Agentic Skills Top 10 — agentic supply-chain vulnerability | `CodeAssessmentService` blocks on a HIGH/CRITICAL finding; `codetrust-blocked` |

Scenarios 10-12 were added for the SOC Validation Module (improvement_plan.md N1, folded into
AgentShield as a module rather than a separate product). A 13th scenario from that plan,
certificate-expiry-near-miss, is **not implemented** — it's a TrustAtlas concept (certificate
lifecycle) with nothing in this codebase to test against; the `/siem/validation` dashboard lists
it explicitly as "N/A — TrustAtlas scope" rather than silently dropping it.

Resource exhaustion isn't a scripted curl scenario because it requires a stdio or SSE MCP server
that returns an oversized response — there's no bundled demo MCP server for either transport
(only the plain-HTTP mock tools above), and standing one up just for this walkthrough would add
more moving parts than the point warrants. The automated test suite exercises the real limit
against a real subprocess/HTTP connection instead — see the two test names above.

`docs/threat-model.md` also tracks known gaps not yet covered by a demo scenario — see its "Known
gaps" section for anything not listed here.

## Running it by hand

Every step above is a single `POST /api/gateway/invoke` call — see `docs/api.md` for the exact
request/response shape, or just read `scripts/demo-attack-lab.sh`, which is plain `curl`.

## Running it as an automated, assertable check

`com.agentshield.siem.AttackSimulatorService` (see `docs/api.md` "SIEM export and detection
validation") replays scenarios 0-9, 11, and 12 above in-process (12 total) — not by shelling out to
this script — and asserts the expected `DetectionRule` fired for each, so a broken control fails a
test instead of requiring a human to eyeball curl output. Run it via `POST /api/siem/validate` /
`POST /api/siem/validation/scenarios/run` (demo profile, ADMIN/SECURITY_ANALYST) or as part of the
test suite (`AttackSimulatorIntegrationTest`). Each run's pass/fail is persisted and shown on the
"Detection Coverage" (`/siem/coverage`) and "SOC Validation" (`/siem/validation`) dashboards
alongside when each rule last fired in real traffic. Scenario 10 (MCP token misuse) is validated
separately by `McpTokenMisuseAttackScenarioTest` — see "SOC Validation Module" in `docs/api.md` for
why it can't run through the same in-process simulator.
