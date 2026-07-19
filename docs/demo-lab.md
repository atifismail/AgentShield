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

After running it, open the **Audit** and **Incidents** pages in the UI (default admin login —
see `docs/operations.md`) to see the full trail each scenario left behind, correlated by request.

## Risk mapping

Each attack scenario demonstrates a control against a specific, named risk category
(`docs/threat-model.md` has the full writeup of each):

| Scenario | Risk category | Control that blocks/detects it |
|---|---|---|
| 1. Tool schema drift | OWASP Agentic Skills Top 10 — supply-chain compromise / update drift; threat-model §1 Tool poisoning | Fingerprint hash comparison, `deny-schema-drift` policy rule |
| 2. PROD destructive action | OWASP Agentic AI Top 10 — excessive agency; threat-model §2 Excessive agency | `deny-prod-destructive-without-approval` policy rule (no approval path for this category by design) |
| 3. Secret-like response | OWASP LLM Top 10 — sensitive information disclosure; threat-model §4 Prompt and response injection | `SecretDetector` + `deny-secret-external-transfer` policy rule |
| 4. Prompt-injected response | OWASP LLM Top 10 — prompt injection; OWASP Agentic AI Top 10 — agent behavior hijacking; threat-model §4 | `PromptInjectionDetector` + `deny-prompt-injection-response` policy rule |
| 5. External transfer approval | OWASP Agentic AI Top 10 — excessive agency (human-in-the-loop); threat-model §2 | `require-approval-external-transfer` policy rule, approval workflow |

`docs/threat-model.md` also tracks known gaps not yet covered by a demo scenario — MCP
confused-deputy risk, tool/skill supply-chain provenance (signing/pinning), and weak local-tool
isolation — see its "Known gaps" section.

## Running it by hand

Every step above is a single `POST /api/gateway/invoke` call — see `docs/api.md` for the exact
request/response shape, or just read `scripts/demo-attack-lab.sh`, which is plain `curl`.
