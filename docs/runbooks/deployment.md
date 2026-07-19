# Runbook: Deployment

Deploying a new release or a configuration change to a production AgentShield instance.

## Before deploying

1. Confirm CI is green on the commit you're deploying — `.github/workflows/ci.yml` runs the full
   test suite, CodeQL, and a container scan on every push to `main`.
2. Check `.github/dependabot.yml`-opened PRs and the Security tab for anything CRITICAL that
   should be pulled in first.
3. Read the changelog/commit messages since the last deploy for anything requiring a manual step
   (a new Flyway migration, a new required environment variable, a config default change).
4. If this deploy adds a new Flyway migration: confirm it's additive (per this project's
   convention — see `docs/architecture.md` and recent `V*.sql` files for examples) so a rollback
   to the previous app version doesn't leave the schema in a state the old code can't read.

## Deploying (Kubernetes / Helm)

```bash
helm upgrade agentshield ./helm/agentshield --set image.tag=<new-tag>
kubectl rollout status deployment/agentshield-agentshield
```

Watch the rollout: `helm/agentshield/values.yaml`'s readiness probe (`/actuator/health/readiness`)
gates traffic — a pod that fails readiness (e.g. can't reach the database, or a Flyway migration
failed) never receives traffic, so a bad deploy should fail safely rather than serve errors.

## Deploying (Docker Compose)

```bash
git pull
docker compose up --build -d
docker compose logs -f app   # watch startup; Flyway migration output appears here
curl -f http://localhost:8080/actuator/health
```

## Post-deploy verification

1. `GET /actuator/health` returns `200` with `{"status":"UP"}`.
2. Log into the admin UI and confirm the dashboard loads.
3. Check `GET /api/audit/verify-integrity` (or the Audit page's "Verify Integrity" button) — a
   fresh deploy should never itself break the audit chain, but it's a cheap sanity check.
4. If this deploy touched the gateway/policy engine: run one known-allowed and one known-denied
   call (the demo attack lab's scenario 0 and 2 are good references, or your own tools/agents) to
   confirm the policy engine is still evaluating correctly.
5. Watch `monitoring/prometheus-alerts.yml`'s alerts for 15–30 minutes post-deploy —
   `AgentShieldDenySpike` in particular would catch a policy-engine regression quickly.

## Rollback

**Kubernetes / Helm:**
```bash
helm rollback agentshield
```
Safe as long as no migration in the failed deploy was destructive (see "before deploying" above)
— Flyway does not support automatic down-migrations in this project, so a rollback that needs a
schema rollback too requires a manual, reviewed `DOWN` script; this should be rare given the
additive-migration convention.

**Docker Compose:**
```bash
git checkout <previous-good-commit>
docker compose up --build -d
```

## Configuration changes without a code deploy

Environment-variable-only changes (e.g. rotating `AGENTSHIELD_ADMIN_PASSWORD`, adjusting
`agentshield.gateway.outbound.allowed-hosts`) still require a restart to take effect — Spring Boot
does not hot-reload environment-sourced config. Same verification steps apply after restart.
