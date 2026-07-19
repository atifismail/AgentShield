# Policy Guide

## Default policy rules

AgentShield ships with ten default rules, evaluated in order. The first rule that matches determines the decision (DENY or APPROVAL_REQUIRED); if no rule matches, the request is ALLOWed.

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
| 9 | Agent calls a tool outside its allowed tool groups | DENY |
| 10 | Request payload exceeds the configured maximum size | DENY |

Every decision includes a human-readable reason so an agent developer or reviewer can see exactly why a call was blocked or queued.

**Note on rule 4:** there is no mechanism in this release for granting "prior approval" for a
destructive PROD action — rule 4 always fires and always DENYs. This is a deliberate,
conservative MVP choice (the safest default for the highest-risk action/environment combination);
an approvable path for pre-authorized destructive maintenance windows is a roadmap item, not
something to work around by weakening this rule.

## Policy override precedence

Beyond the 10 fixed rules above, an ADMIN/SECURITY_ANALYST can add database-backed policy
overrides (`POST /api/policy-overrides`) — scoped by any combination of action category,
environment, tool group, and agent, each with its own decision and reason. Evaluation order is
strict and cannot be changed at runtime:

1. **The 10 fixed rules run first, unconditionally, in the order listed above.** The first one
   that matches decides the outcome and evaluation stops right there.
2. **Only if none of the fixed rules match** does the engine consult active overrides, in
   priority order. The first matching override decides the outcome.
3. **Only if no override matches either** is the request ALLOWed.

This means an override can add *extra* restriction (deny something the fixed rules would have
allowed) or grant a scoped extra allowance for a gap the fixed rules leave open — but it can
never weaken or bypass a fixed rule, since those are checked first and always win. For example,
an override cannot un-deny a production destructive action (rule 4) or re-allow a drifted tool
(rule 3); it can only ever affect the space of requests all 10 fixed rules would otherwise ALLOW.
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

The 10 default rules above are fixed Java code. For a rule an operator needs to add or change
without a deployment, use `/api/policy-overrides` (or the "Policy overrides" section on the
Policies page) instead: `{actionCategory, targetEnvironment, toolGroup, agentName, decision,
reason, priority}`, where any match field left blank means "matches anything."

Overrides are checked **after** all 10 fixed rules, and only when those would otherwise `ALLOW`.
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
