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
| Secret detected in response | +40 |
| Prompt injection detected in response | +40 |
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

**Prompt-injection indicators** (checked against tool response text): "ignore previous instructions", "disregard system message", "reveal your secret", "send credentials", "exfiltrate", "call this tool instead", "hidden instruction", "developer message override", "system prompt", "do not tell the user".

**Secret indicators**: AWS access key pattern, private key header, JWT-like token, password assignment, API key assignment, bearer token, database connection URL containing credentials.

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
