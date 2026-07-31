# Explicit Entitlements And Reproducible Evidence — Baseline (Work Package 0)

Date: 2026-07-30

Scope: facts-only baseline and contract inventory for
`agentshield_policy_evidence_execution_plan_2026-07-30.md`, work package 0. No code, schema,
config, or documentation behavior changed in this package.

## 1. Repository state

- Root: `D:\Projects\53_AgentShield`
- Branch: `main`
- `HEAD`: `846aad07925699c717dc5cecb2aa38a2b53429d7` ("Move collapse button fully inside sidebar;
  fix low-contrast active nav link", committed 2026-07-23 20:58:33 +0900)
- `git status --short` at inventory time:
  ```text
   M .gitignore
  ?? .mcp.json
  ?? CLAUDE.md
  ```
  These are pre-existing local changes unrelated to this package (an added
  `.code-review-graph/` ignore line, and two untracked local-tooling files). Left untouched.
- Remote: `origin` → `https://github.com/atifismail/AgentShield.git`.
- Java: installed JDK is Temurin 17.0.16 (`java -version`), but `build.gradle:12` declares
  `languageVersion = JavaLanguageVersion.of(21)` via the Gradle toolchain, and
  `.github/workflows/ci.yml` provisions Temurin 21 explicitly. Gradle's toolchain resolution
  handled this transparently for the local `test`/`build` runs below (no manual JDK 21 install
  was required to get a green build), so this is not a build blocker, but any manual `java`
  invocation outside Gradle on this machine runs on 17, not 21.
- Gradle: 8.10 (wrapper).
- Docker: Docker Desktop 28.4.0, daemon reachable (`docker info` returned host facts), Linux
  containers, so both the Compose smoke path and MariaDB Testcontainers path are usable in this
  environment.

## 2. Test baseline

Command: `./gradlew test` (first run reported `UP-TO-DATE` from a prior local build; re-run with
`--rerun` to force fresh execution and observed output).

- Fresh run result: **BUILD SUCCESSFUL** in 55.383s (test task itself), 2m10s wall time including
  up-to-date compile tasks.
- **269 tests, 0 failures, 0 ignored** (`build/reports/tests/test/index.html`, regenerated
  2026-07-30 19:20 local time in this run).
- No pre-existing failures to classify; no environment-bound skips observed.
- This run exercised the MariaDB Testcontainers path (Docker was available), consistent with
  `AbstractIntegrationTest`'s singleton-container pattern referenced in CI.

## 3. Code-review graph state

The repository's `CLAUDE.md` requires using code-review-graph MCP tools (e.g.
`get_architecture_overview_tool`, `query_graph_tool`) before Grep/Glob/Read, and the scoped
`53_AgentShield:explore-codebase` skill is installed and expects those same MCP tools. In this
session, none of the graph MCP tools resolved (checked via tool search); the graph server is not
connected/available here, so it could not be refreshed or queried. Inventory below was produced
by direct `Grep`/`Glob`/`Read`, as CLAUDE.md permits when the graph doesn't cover what's needed.
A subsequent agent that does have the graph MCP server connected should refresh it against this
`HEAD` before relying on it for work packages 1+.

## 4. Endpoint inventory (controllers named in the execution plan, plus adjacent ones sharing a role boundary)

Role guards below come from `security/SecurityConfig.java` `requestMatchers` (no
`@PreAuthorize` annotations are used on these controllers; authorization is centralized in
`SecurityConfig`).

### `tool/ToolController.java` — `/api/tools`
| Method | Path | Role guard |
|---|---|---|
| POST | `/api/tools` | none matched (authenticated only, no specific rule) |
| GET | `/api/tools` | none matched |
| GET | `/api/tools/{id}` | none matched |
| GET | `/api/tools/{id}/versions` | none matched |
| POST | `/api/tools/{id}/refresh` | none matched |
| POST | `/api/tools/{id}/approve` | `ADMIN, TOOL_OWNER, SECURITY_ANALYST` |
| POST | `/api/tools/{id}/reject` | `ADMIN, TOOL_OWNER, SECURITY_ANALYST` |
| GET | `/api/tools/{id}/provenance` | `ADMIN, SECURITY_ANALYST` (matches `/api/tools/*/provenance/**`) |
| POST | `/api/tools/{id}/provenance/verify` | `ADMIN, SECURITY_ANALYST` |
| POST | `/api/tools/{id}/provenance/revoke` | `ADMIN, SECURITY_ANALYST` |

### `mcp/McpServerController.java` — `/api/mcp-servers`
| Method | Path | Role guard |
|---|---|---|
| POST | `/api/mcp-servers` | none matched |
| GET | `/api/mcp-servers` | none matched |
| GET | `/api/mcp-servers/{id}` | none matched |
| POST | `/api/mcp-servers/{id}/discover` | none matched |
| GET | `/api/mcp-servers/{id}/stdio/status` | `ADMIN, SECURITY_ANALYST` |
| POST | `/api/mcp-servers/{id}/stdio/start` | `ADMIN` |
| POST | `/api/mcp-servers/{id}/stdio/stop` | `ADMIN` |
| GET | `/api/mcp-servers/{id}/sse/status` | `ADMIN, SECURITY_ANALYST` |
| POST | `/api/mcp-servers/{id}/sse/start` | `ADMIN` |
| POST | `/api/mcp-servers/{id}/sse/stop` | `ADMIN` |

No `GET /api/mcp-servers/{id}/tools` (MCP-scoped tool listing) and no
`POST /api/mcp-servers/{id}/proxy` route exist today — both are new surface for work package 1,
confirming `ROADMAP.md`'s "Planned — API surface reconciliation" section.

### `gateway/GatewayController.java` — `/api/gateway`
| Method | Path | Role guard |
|---|---|---|
| POST | `/api/gateway/invoke` | `permitAll()` (agent credential auth is enforced inside the handler, not at the Spring Security filter layer) |

### `approval/ApprovalController.java` — `/api/approvals`
| Method | Path | Role guard |
|---|---|---|
| GET | `/api/approvals` | none matched |
| GET | `/api/approvals/{id}` | none matched |
| POST | `/api/approvals/{id}/approve` | `ADMIN, APPROVER` |
| POST | `/api/approvals/{id}/reject` | `ADMIN, APPROVER` |

### `policy/PolicyController.java` — `/api/policies`
| Method | Path | Role guard |
|---|---|---|
| GET | `/api/policies` | `ADMIN, SECURITY_ANALYST` |
| GET | `/api/policies/{name}/versions` | `ADMIN, SECURITY_ANALYST` |
| POST | `/api/policies` | `ADMIN, SECURITY_ANALYST` |
| POST | `/api/policies/{id}/enable` | `ADMIN, SECURITY_ANALYST` |
| POST | `/api/policies/{id}/disable` | `ADMIN, SECURITY_ANALYST` |
| POST | `/api/policies/dry-run` | `ADMIN, SECURITY_ANALYST` |
| GET | `/api/policies/replay/{gatewayRequestId}` | `ADMIN, SECURITY_ANALYST` |

### `governance/GovernanceController.java` — `/api/governance`
| Method | Path | Role guard |
|---|---|---|
| GET | `/api/governance/report` | `ADMIN, SECURITY_ANALYST` |
| GET | `/api/governance/report?format=markdown` | `ADMIN, SECURITY_ANALYST` |

No JSON/SARIF `evidence` export endpoint exists yet (work package 5 territory); the only current
export is the markdown/JSON governance report.

### `agent/AgentController.java` — `/api/agents`
| Method | Path | Role guard |
|---|---|---|
| POST / GET / GET{id} / PUT{id} / enable / disable / credentials* / rotate-token / DELETE{id} | `/api/agents/**` | `ADMIN` (blanket) |

No `agent_tool_grants` sub-resource (`/api/agents/{id}/grants`) exists yet — confirms work
package 2 is genuinely additive, not a rename.

## 5. Domain contract facts relevant to work packages 1–5

- **`tool/Tool.java`** current persisted fields: `id, name, type, toolGroup, endpointUrl, owner,
  environment, description, schemaJson, approvedHash, currentHash, approvalStatus, sourceType,
  lastSeenAt, createdAt, updatedAt, mcpServerId, mcpToolName`. There is one combined
  `approvedHash`/`currentHash` pair — no separate description/input-schema/output-schema hashes,
  no `riskTier`, no `defaultAction`, no `fingerprintFormatVersion` yet. This matches the plan's
  instruction not to backfill split hashes from the combined one.
- **`policy/PolicyEngine.java`**: fixed rules run first and only fall through to DB policy
  overrides when every fixed rule would otherwise `ALLOW` (see class Javadoc and the DENY/
  APPROVAL_REQUIRED branches preceding the override lookup). This is the ordering invariant #1 in
  the execution plan and is already true of the current engine — grant/profile work must be
  inserted without disturbing this order.
- **`approval/ApprovalService.java`**: single-use enforcement is via `requirePending(id)`, which
  calls `repository.findByIdForUpdate(id)` (pessimistic row lock) and throws `ConflictException`
  if the request is expired or not `PENDING`. This is the exact replay-protection path work
  package 3 must reuse unchanged.
- **`mcp/` package**: 26 files including a distinct `McpConsentController`/`McpConsentService`
  (`/api/mcp-consents`, role `ADMIN, SECURITY_ANALYST`) already gating MCP-backed tool calls,
  separate from `McpServerController`. Also present: `StdioMcpProcessManager`,
  `StdioCommandValidator`, `McpTokenEncryptor`, `McpOAuthTokenService` — an existing consent/
  transport/credential model that work packages 1–2 must reuse, not replace.
- **`audit/`, `governance/GovernanceReportService.java`**: existing tests include
  `governance/GovernanceReportIntegrationTest.java` and `policy/PolicyReplayIntegrationTest.java`.
  Only 1 test file currently lives directly under `governance/`; work package 5's evidence-export
  tests are new coverage, not an extension of an already-large suite.

## 6. Flyway migration inventory

Highest paired version: **V19** in both dialects, identical version numbers and file naming
present in both:

`src/main/resources/db/migration/postgresql/` and
`src/main/resources/db/migration/mariadb/`:
`V1__init.sql` … `V19__soc_validation.sql` (19 versions, one-to-one filename match by version
number across both directories — no divergence detected). The next available paired version for
work package 1 is **V20**.

## 7. Test file distribution (existing coverage surface, by package under `src/test/java/com/agentshield/`)

`mcp` 10, `support` 6, `siem` 6, `tool` 4, `gateway` 4, `codetrust` 4, `risk` 3, `policy` 3,
`dlp` 3, `security` 2, `metrics` 2, `incident` 2, `config` 2, `behavior` 2, `audit` 2,
`approval` 2, `web` 1, `governance` 1, `common` 1, `agent` 1, plus two top-level test classes
(`AgentShieldApplicationTests`, `DomainPersistenceTests`).

`approval` (2 files) and `governance` (1 file) are the thinnest of the packages this release
touches most (grants, profiles, evidence export) — expect new test files there, not just
additions to existing ones.

## 8. GitHub repository protection and access facts

**Not determined in this session.** The `gh` CLI is not installed/authenticated in this
environment (`gh: command not found`), and no GitHub API call was made (per the plan's "facts-
only; do not modify GitHub settings" instruction, and because an unauthenticated call could not
return ruleset/role data for a private-by-default check anyway). What is locally verifiable:

- `origin` remote is `https://github.com/atifismail/AgentShield.git`.
- `.github/workflows/ci.yml` defines a `build-and-test` job (`./gradlew build`), a `codeql`
  job, and a `container-scan` (Trivy, report-only, `exit-code: 0`) job — i.e. the check name a
  `protect-default-branch` ruleset would need to require is `Build and test` / `build-and-test`.
- `.github/dependabot.yml` exists (contents not required for this package).

A subsequent task with repository-admin API access (or the owner running `gh api
repos/atifismail/AgentShield/rulesets`) is required to record actual ruleset, branch-protection,
collaborator-role, deploy-key, GitHub App, and Actions-secret state before work package 6's
release gate.

## 9. What is safe to extend (acceptance check)

- Work package 1 can add `description_hash`, `input_schema_hash`, `output_schema_hash`,
  `risk_tier`, `default_action`, `fingerprint_format_version` to `tools` via `V20` in both
  migration directories without touching `approved_hash`/`current_hash`.
- Work package 1's new endpoints (`GET /api/mcp-servers/{id}/tools`,
  `POST /api/mcp-servers/{id}/proxy`) are net-new paths; no existing route collides.
  `SecurityConfig` will need explicit new `requestMatchers` entries for them (none exist yet)
  since unmatched authenticated paths currently fall through to default authenticated-user
  access — the specific role for the new routes must be decided in work package 1, not left
  unmatched by omission.
- Work package 2's `agent_tool_grants` table and `/api/agents/{id}/grants` endpoints are net-new;
  `Agent.allowedToolGroups` (legacy string) is untouched by this package.
- Work package 3's `approval_profiles` table and `approval_profile_id`/`assigned_role` columns on
  `approval_requests` are net-new; `requirePending()`'s row-locking single-use path is unchanged.
- Work package 4's `evaluation_*` tables are entirely new; nothing in `gateway/` or `mcp/`
  currently has a "no-forwarding" test mode to reuse — it must be built from the existing
  pre-call policy components only.
- Work package 5 has no existing JSON/SARIF evidence endpoint or `docs/schemas/` directory to
  extend (`docs/schemas/` does not currently exist under `docs/`) — this is new surface, and it
  must consume the work package 1–4 domain types rather than duplicate them.

## 10. No behavior change

No source, test, migration, or documentation file's behavior was modified to produce this
inventory. The only filesystem change from this package is this document.
