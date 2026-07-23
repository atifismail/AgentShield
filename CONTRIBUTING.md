# Contributing to AgentShield

Thanks for considering a contribution. This file covers the human-contributor workflow —
opening issues, submitting PRs, running the build. For the technical architecture, fixed
technology decisions, and repository layout, see [`AGENTS.md`](AGENTS.md) and
[`PROJECT_PLAN.md`](PROJECT_PLAN.md).

## Before you start

- Check open issues and PRs first to avoid duplicate work.
- For anything beyond a small fix (new module, new API surface, a change to policy/risk
  semantics), open an issue to discuss the approach before writing code. `docs/threat-model.md`
  and `docs/architecture.md` explain the design constraints most changes need to respect.
- Issues labeled `good first issue` are scoped for a first contribution.

## Building and testing

```bash
# Compile
./gradlew compileJava compileTestJava

# Full test suite — needs a running Docker daemon (Testcontainers spins up real MariaDB)
./gradlew test

# Run the app locally
docker compose up          # app + PostgreSQL
./gradlew bootRun          # against a local PostgreSQL you provide
```

A PR should include tests for the behavior it changes (unit or integration, matching the
existing style in `src/test/java`), and `./gradlew test` should pass locally before you open it.

## Code expectations

- Keep changes scoped to what the issue/PR describes — no drive-by reformatting of unrelated
  files.
- Match the existing package-per-module layout (`AGENTS.md` § "Repository layout") and the fixed
  technology decisions there (Gradle, no SPA framework, no paid/cloud-only services required to
  run the core product).
- Fail-closed by default: any new control that can error should deny on error, not silently
  allow (see `AGENTS.md` and existing detectors/policy code for the pattern).
- Never log or persist raw secrets, tokens, or matched detector text — only indicator
  name/category/confidence, consistent with `SecretDetector`/`PiiDetector`/`DlpScanService`.

## Reporting a security issue

Please do not open a public issue for a suspected vulnerability. Instead, use this repository's
GitHub Security tab ("Report a vulnerability" / private security advisory), or contact the
maintainers directly if that option isn't available to you. Include enough detail to reproduce
the issue; `docs/threat-model.md` describes the risks this project already defends against, which
may help you scope the report.

## Pull requests

- One logical change per PR.
- Describe what changed and why, not just what — the diff already shows what.
- Link the issue it resolves, if any.
- CI must pass; a maintainer will review and may ask for changes before merging.
