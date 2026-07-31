# Policy Guide

## Default policy rules

AgentShield ships with eleven default rules, evaluated in order. The first rule that matches determines the decision (DENY or APPROVAL_REQUIRED); if no rule matches, the request is ALLOWed.

| # | Rule | Decision |
|---|------|----------|
| 1 | Disabled agent | DENY |
| 2 | Unapproved tool | DENY |
| 3 | Tool has schema/description drift | DENY |
| 4 | Production destructive action without prior approval | DENY |
| 5 | Production write action | APPROVAL_REQUIRED |
| 6 | External data transfer | APPROVAL_REQUIRED |
| 7 | Response contains a secret-like value and destination is external | DENY |
| 8 | Tool response contains a prompt-injection pattern | DENY |
| 9 | Agent calls a tool outside its allowed tool groups **or** has no matching grant (governed by `agentshield.grants.transition-mode` — see "Grants" below) | DENY |
| 10 | Request payload exceeds the configured maximum size | DENY |
| 11 | MCP-backed tool: agent has no active MCP consent grant | DENY |

Every decision includes a human-readable reason so an agent developer or reviewer can see exactly why a call was blocked or queued.

**Note on rule 4:** there is no mechanism in this release for granting "prior approval" for a
destructive PROD action — rule 4 always fires and always DENYs. This is a deliberate,
conservative MVP choice (the safest default for the highest-risk action/environment combination);
an approvable path for pre-authorized destructive maintenance windows is a roadmap item, not
something to work around by weakening this rule.

**Note on rule 11:** this is AgentShield's confused-deputy control for MCP (see
`docs/threat-model.md` and `docs/architecture.md`). It only fires for tools discovered from an
MCP server (`Tool.isMcpBacked()`) — plain HTTP tools are unaffected. A tool being `APPROVED` in
the tool registry is necessary but not sufficient for an MCP-backed tool: the calling agent must
also hold an ACTIVE, unexpired `McpConsent` grant for that MCP server, scoped to any combination
of tool name and action category (a null-scoped field on the grant means "any"). Grant and manage
consents at `POST /api/mcp-consents` / the MCP page in the admin UI.

**Note on rule 3 and supply-chain provenance:** rule 3 is also the enforcement point for a failed
or revoked tool signature (`docs/api.md` "Supply-chain provenance") — a `SIGNATURE_FAILED` or
`REVOKED` provenance record forces `Tool.approvalStatus` to `DRIFTED` directly, blocking calls
immediately without waiting for a fingerprint refresh, and reusing this same rule rather than a
separate one. Whether a *new* approval requires a verified signature at all is a separate,
earlier check (at `POST /api/tools/{id}/approve` time, not a gateway policy rule) — see
`docs/operations.md` for the `agentshield.provenance.require-signature-for` trust policy.

## Grants (explicit per-agent tool access)

Rule 9 above is governed by `agentshield.grants.transition-mode`:

| Mode | Behavior |
|---|---|
| `GROUPS_ONLY` (default) | Only `Agent.allowedToolGroups` is consulted. Grants are never read. Every existing installation keeps today's exact behavior until an operator explicitly changes this. |
| `GRANTS_OR_GROUPS` | If any grant (any status) exists for the agent/tool pair, grants alone decide; otherwise the legacy group check still applies. Use this to migrate one agent/tool pair at a time. |
| `GRANTS_REQUIRED` | Grants alone decide. The legacy group string is never consulted, even if it would have allowed the call. Use for new deployments/demos once the grant model is the intended source of truth. |

**Migration path:** start every existing installation at `GROUPS_ONLY` (the default — no action
needed). To adopt grants, switch to `GRANTS_OR_GROUPS`, create grants for the agent/tool pairs
that need them, verify behavior, then switch those pairs (or the whole deployment) to
`GRANTS_REQUIRED` once every pair that needs access has an explicit grant. Never flip an existing
production deployment straight to `GRANTS_REQUIRED` — an agent/tool pair with no grant yet is
denied outright in that mode, with no group fallback.

A grant (`POST /api/agents/{id}/grants`, ADMIN only) may optionally restrict by `actionCategory`,
`targetEnvironment`, `resourcePathPattern`, and `requiredTokenScope`; a null field on a grant means
"not restricted on that dimension." A grant must be `ACTIVE` and within its `notBefore`/
`expiresAt` window, and every restriction it declares must match, or it doesn't count — an active
grant with the wrong action/environment/resource/scope is exactly as if no grant existed. Grants
are read live from the database on every gateway call (no caching), so a revoke takes effect on
the very next invocation.

**Resource path pattern grammar** (`resourcePathPattern`) is a small glob, not a regex: it must be
anchored (start with `/`), `*` matches within one path segment only (never across a `/`), and it
rejects `..`, backslashes, a URL scheme (`:`), control characters, `**`, and regex metacharacters
(`[ ] ( ) + ? { } ^ $ |` and backslash). Example: `/repos/*/pulls` matches `/repos/agentshield/pulls`
but not `/repos/agentshield/nested/pulls`.

**Non-goal:** resource-path/token-scope restrictions can only ever be satisfied for a tool that has
a specifically reviewed `ToolAuthorizationNormalizer` extracting those facts from its typed input —
release one ships zero normalizers, so a grant with either restriction is not yet satisfiable for
any tool. Do not configure one expecting an ALLOW; it exists so the grant *shape* is ready once a
normalizer is added and reviewed for a specific tool. AgentShield never authorizes from
`InvokeRequest.context`, a model's own explanation text, or an unreviewed admin-configured
JSONPath — only a documented, code-reviewed extraction path.

## Approval routing profiles

An `ApprovalProfile` (`POST /api/approval-profiles`, ADMIN only) routes an already-
`APPROVAL_REQUIRED` request (rules 5/6 above, or a DLP `APPROVAL_REQUIRED` finding) to a specific
human role — it never changes the ALLOW/DENY/APPROVAL_REQUIRED decision itself. Resolution picks
the highest-`priority` **enabled** profile whose every declared predicate (agent/tool/tool-group/
action-category/environment/risk-tier — each optional, null means "not restricted") matches, once,
at the moment the approval is created; a profile edited or disabled later never changes an
already-created approval's routing. When no profile matches, the pre-existing default expiration
and ADMIN/APPROVER-only behavior applies unchanged. The approving user must hold the resolved role
(or be ADMIN, which always passes — a documented override). Creating or re-enabling a profile that
would be ambiguous with another enabled profile at the same priority (identical predicates) is
rejected as a configuration error.

## Policy evaluation engine (no-tool-forwarding simulation)

`POST /api/evaluations/suites`/`/api/evaluations/runs` run a versioned suite of synthetic fixtures
through the real policy/grant/MCP-consent components with **zero tool forwarding** — useful for
testing a policy, grant, or tool change before relying on it in production. See `docs/api.md`
"Policy evaluations" for the endpoint reference and the shipped default suite's fixture
categories. A suite is immutable once created — importing again under the same name always
creates a new version, never edits one in place.

## Policy override precedence

Beyond the 11 fixed rules above, an ADMIN/SECURITY_ANALYST can add database-backed policy
overrides (`POST /api/policy-overrides`) — scoped by any combination of action category,
environment, tool group, and agent, each with its own decision and reason. Evaluation order is
strict and cannot be changed at runtime:

1. **The 11 fixed rules run first, unconditionally, in the order listed above.** The first one
   that matches decides the outcome and evaluation stops right there.
2. **Only if none of the fixed rules match** does the engine consult active overrides, in
   priority order. The first matching override decides the outcome.
3. **Only if no override matches either** is the request ALLOWed.

This means an override can add *extra* restriction (deny something the fixed rules would have
allowed) or grant a scoped extra allowance for a gap the fixed rules leave open — but it can
never weaken or bypass a fixed rule, since those are checked first and always win. For example,
an override cannot un-deny a production destructive action (rule 4), re-allow a drifted tool
(rule 3), or bypass a missing MCP consent grant (rule 11) — it can only ever affect the space of
requests all 11 fixed rules would otherwise ALLOW.
Use `POST /api/policies/dry-run` to test a hypothetical request against the full evaluation order
above (fixed rules, then active overrides) before relying on a policy or override change.

## Risk scoring

Risk is scored deterministically, not with a model:

**Base score by action category**

| Category | Score |
|---|---|
| READ | 10 |
| WRITE | 40 |
| DESTRUCTIVE | 70 |
| CREDENTIAL_ACCESS | 90 |
| EXTERNAL_TRANSFER | 80 |

**Modifiers**

| Condition | Adjustment |
|---|---|
| Target environment is PROD | +20 |
| Tool not approved | +50 |
| Schema drift detected | +50 |
| Secret detected in response, confidence HIGH / MEDIUM / LOW | +40 / +25 / +10 |
| Prompt injection detected in response, confidence HIGH / MEDIUM / LOW | +40 / +25 / +10 |
| First time this agent/tool pair has been seen | +10 |
| Human approval already granted | -30 |

**Risk levels**

| Score range | Level |
|---|---|
| 0-29 | LOW |
| 30-59 | MEDIUM |
| 60-89 | HIGH |
| 90+ | CRITICAL |

## Detection patterns

Every match carries a **category**, a **confidence** (LOW/MEDIUM/HIGH), and its line/offset within
the scanned text — never the matched text itself, which is never returned, logged, or persisted.
Category and confidence feed directly into risk scoring (above) and are shown on the incident
detail page for anything the detector blocked.

**Prompt-injection indicators** (checked against tool response text):

| Indicator | Category | Confidence |
|---|---|---|
| "ignore previous instructions" | PROMPT_OVERRIDE | HIGH |
| "disregard system message" | PROMPT_OVERRIDE | HIGH |
| "developer message override" | PROMPT_OVERRIDE | HIGH |
| "system prompt" | PROMPT_OVERRIDE | LOW |
| "reveal your secret" | HIDDEN_INSTRUCTION | HIGH |
| "send credentials" | HIDDEN_INSTRUCTION | HIGH |
| "do not tell the user" | HIDDEN_INSTRUCTION | HIGH |
| "exfiltrate" | HIDDEN_INSTRUCTION | MEDIUM |
| "hidden instruction" | HIDDEN_INSTRUCTION | MEDIUM |
| "call this tool instead" | TOOL_REDIRECTION | HIGH |

**Secret indicators**:

| Indicator | Category | Confidence |
|---|---|---|
| AWS access key pattern | CREDENTIAL | HIGH |
| GitHub token-like value (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`) | TOKEN | HIGH |
| Private key header (PEM) | PRIVATE_KEY | HIGH |
| Database connection URL containing credentials | DB_CONNECTION_STRING | HIGH |
| JWT-like token | TOKEN | MEDIUM |
| Password assignment | CREDENTIAL | MEDIUM |
| API key assignment | CREDENTIAL | MEDIUM |
| Bearer token | TOKEN | MEDIUM |

A small allowlist filters common placeholder values (`changeme`, `redacted`, `example`, `<your-api-key>`,
and similar) out of the secret detector's matches — checked per-match, not per-response, so a real
secret elsewhere in the same response is still caught even if a placeholder also appears in it.

Both detectors are deterministic (pattern/regex based) so the product runs fully offline with no dependency on a paid classification API. A future phase may add local LLM-assisted classification as a supplement, never a replacement.

## Versioning and dry-run

Policies are versioned by name (`policies` table: `name` + `version`, only one version `enabled` at a time). Before enabling a new policy version, use the dry-run evaluation endpoint to test it against a hypothetical request — this evaluates the rules without creating a `GatewayRequest` or any audit trail.

## Policy overrides (no code change required)

The 11 default rules above are fixed Java code. For a rule an operator needs to add or change
without a deployment, use `/api/policy-overrides` (or the "Policy overrides" section on the
Policies page) instead: `{actionCategory, targetEnvironment, toolGroup, agentName, decision,
reason, priority}`, where any match field left blank means "matches anything."

Overrides are checked **after** all 11 fixed rules, and only when those would otherwise `ALLOW`.
That ordering is deliberate: an override can add extra restriction, or a deliberately scoped
extra allowance, but it can never undo a fixed `DENY` or `APPROVAL_REQUIRED` — a disabled agent
stays denied, a destructive PROD action stays blocked, no override can change that. When multiple
overrides match, the one with the lowest `priority` number wins. Every override create, enable,
disable, and delete is audited.

## Extending the evaluator (OPA, etc.)

`PolicyEngine` implements a small `PolicyEvaluator` interface (`evaluateRequest` /
`evaluateResponse`). `OpaPolicyEvaluator` exists as a documented extension point for a future Open
Policy Agent sidecar integration but is intentionally unimplemented and not wired into Spring —
AgentShield must not require a paid or external service for its MVP.
