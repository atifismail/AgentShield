# Support

AgentShield is open source (GPLv3 — see [`LICENSE`](LICENSE)) and built to solve a real problem
end to end without requiring a paid add-on. This page describes what's covered by the community
edition versus what's reserved for commercial support, and how to get help either way.

## Community support (free)

- **Issues** — bug reports and feature requests via GitHub Issues.
- **Discussions** — usage questions, design questions, "how would I configure X" via GitHub
  Discussions (or Issues if Discussions isn't enabled on this repo yet).
- **Documentation** — [`docs/`](docs) covers architecture, threat model, policy configuration,
  the REST API, deployment (Docker Compose, Helm, Kubernetes), and operations. Start with the
  [README](README.md) quickstart and [`docs/demo-lab.md`](docs/demo-lab.md).
- **What's included in the open-source edition** — single-node deployment, the full gateway/policy/
  risk/DLP/approval/audit engine, MCP registration and tool discovery, the code-trust workflow,
  SIEM export and detection validation, and the operator dashboard. Nothing load-bearing is held
  back from the community edition; see [`README.md`](README.md#project-status) for the current
  feature list.

Response times on community channels are best-effort; there's no SLA.

## Commercial support

For teams that need guarantees rather than best-effort help, the following are available on a
paid basis (contact the maintainers to discuss scope — see the repository's contact/organization
page):

- **Support subscriptions** with response-time SLAs.
- **Deployment hardening** — production readiness review against `docs/operations.md` and
  `docs/threat-model.md` for your specific environment.
- **Connector development** — SIEM/SOAR/ticketing/CA/HSM integrations beyond the generic exports
  this repo ships with.
- **Custom policy and detection-rule packs** tailored to your environment.
- **Readiness assessments and migration consulting** for rolling AgentShield out across an
  existing agent/tool estate.
- **Managed deployment.**

A dual-license or separate enterprise-license option is under consideration for organizations
whose compliance requirements don't fit GPLv3's copyleft terms — no such license exists yet;
today, all usage is under the GPLv3 terms in [`LICENSE`](LICENSE). If this matters for your
organization, open an issue or reach out so it can inform the decision.

## Reporting a security issue

See [`CONTRIBUTING.md`](CONTRIBUTING.md#reporting-a-security-issue) — please don't file security
vulnerabilities as public issues.
