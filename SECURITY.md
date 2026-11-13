# Security policy

## Supported versions

ALES INVARIANT is pre-1.0. Only the latest minor release line (currently 0.3.x, developed on `main`) receives security fixes; older minors do not. There are no long-term-support branches. When a stable release is made, this section will list the supported release lines.

## Reporting a vulnerability

Do not open a public issue for a security problem.

**Contact channel: GitHub private security advisories only.** Use the "Report a vulnerability" button on the repository's Security tab (Security > Advisories > Report a vulnerability). Do not send reports by email or direct message; no personal addresses are published for this purpose. Include:

- the affected component and version or commit;
- steps to reproduce, or a failing test;
- the impact you observed, and whether you believe it is reachable without special configuration.

We will acknowledge receipt, confirm whether we can reproduce the issue, and keep you informed of progress in the advisory thread.

## Disclosure timeline

We follow coordinated disclosure with a 90-day window from the date we receive a report. We aim to ship a fix sooner where that is practical. If a fix is not ready within 90 days, we will discuss the timeline with you in the advisory, and we may publish the advisory with mitigations when the issue is already public or actively exploited.

## Scope

In scope:

- **The enforcement boundary.** Any path where a derivative marked as denied by the runtime is returned to a caller through an instrumented adapter, or where an authorization decision is computed incorrectly. This includes UNKNOWN being treated as ALLOW for protected data.
- **Signing.** Forged or accepted envelopes and revocation events with invalid Ed25519 signatures, canonicalization flaws that let two different objects share a signature, and key material appearing in configuration or logs.
- **Tenant isolation.** Any way for one tenant to read, revoke or infer another tenant's objects through the graph, epochs, caches or APIs.
- **Propagation.** Any way a derivative can be more permissive than its parents under the rules in `spec/SPEC.md`.

## Out of scope

- Denial of service against the demo stack in `deploy/`, including resource exhaustion, which is not hardened for production.
- Issues in upstream dependencies (FastAPI, Pydantic, SQLAlchemy, Redis, PostgreSQL, Docker images and similar). Report those to their maintainers. We will track and update our pinned versions when fixes are available.
- Information that a person or model has already seen before a revocation. This is a documented non-guarantee (see `docs/guarantees.md`).
- Findings that depend on an uninstrumented or bypass path that the documentation already marks as not governed.
- Social engineering, physical attacks, and findings from automated scanners without a demonstrated impact.

## Known risks

The public risk register is [docs/residual-risks.md](docs/residual-risks.md). Check it before reporting: documented residual risks and non-guarantees (for example uninstrumented paths, no token revocation list, no recall of disclosed content) are out of scope unless you show the documented mitigation fails.

Thank you for helping keep the project and its users safe.
