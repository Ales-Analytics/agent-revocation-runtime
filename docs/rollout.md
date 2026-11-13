# Progressive rollout

How to move an integration from observing to enforcing, how to read coverage at each step, and how to roll back. The fail modes are defined in [integration-guide.md](integration-guide.md) and `sdk-python/ales_sdk/fail_modes.py`; exposure windows are in [product.md](product.md) and [guarantees.md](guarantees.md).

## Path per integration

Do this one integration (one retrieval path, one cache, one model call site) at a time.

| Stage | Fail mode | What happens on a non-ALLOW decision | Coverage label | Exit criteria |
|---|---|---|---|---|
| 1. Observe | `OBSERVE` | Content is used. The decision is logged and counted as `observed_only`. | `OBSERVE_ONLY`: excluded from every coverage claim | Lineage is registered for sources and derivatives; no unexpected `UNKNOWN` / `OBJECT_UNKNOWN` for content that should be tracked; `DecisionSummary.untracked` is understood |
| 2. Warn | `WARN` | Protected content is held and needs an operator override; `public` content passes as observed-only. | Not a protection guarantee; not counted as enforcing | Every denial in the log was expected; false denials fixed at the source (envelope scopes, purpose, lineage) |
| 3. Enforce | `ENFORCE` | `DENY`, `UNKNOWN` (protected), `QUARANTINE`, `REFRESH` and other non-ALLOW decisions block use. | `ENFORCING` once the adapter's conformance checks pass | Coverage check below is clean; purge targets configured |
| 4. Harden (optional) | `BOUNDED_OFFLINE` | As `ENFORCE`, plus a signed snapshot lease for control-plane outages; protected reads are denied after the lease expires. | As `ENFORCE` | The lease value is chosen and published as the outage exposure window |

Server-side controls ramp the same way: start `ALES_ENFORCE_WORKLOADS=auto`, move to `strict` (the default under `ALES_ENV=production`) after every agent is registered and granted; add `risk_floors` per purpose last. Tenants that have registered no workloads are not identity-checked in `auto` (R36).

## How to read coverage

| Signal | Where | Reads as |
|---|---|---|
| Adapter level (ENFORCING, INGESTION_ONLY, NON_ENFORCING) and per-check results | `conformance/report.md`, mirrored in [coverage-matrix.md](coverage-matrix.md) | Whether the adapter's guarded read path blocks a revoked derivative. `INGESTION_ONLY` rows verify a source connector, not read-time enforcement. A pass says nothing about direct store access |
| Per-call model coverage | `DecisionSummary.coverage` (`tracked / total`; 1.0 when empty) from the model gateway, with `untracked`, `blocked_untracked`, `exempt`, `observed_only`, `offline` | Share of context items that carried an ALES id and were authorized. Below 1.0 means untracked content reached or was removed from the prompt; see R2 for the `untracked` modes and exempt roles |
| Environment and wiring | `python -m ales_server.preflight` (`--json` for machine output) | PASS / WARN / FAIL table for the current environment, exit 1 on any FAIL. It applies the same production rules as `create_app()` startup and checks the database, migration revision, snapshot key, tokens/OIDC, denylist and purge-target configuration structurally; it does not contact purge stores or the JWKS URI. It does not check that your retrieval paths call `authorize` or the freshness guard. Run it before each stage change and after every deploy |
| Purge wiring | `GET /v1/outbox/stats`: `worker.handlers` must show `purge:...`, not `log_only`; watch `dead` | Whether physical deletion is actually configured (R10, R11) |
| Connector freshness | `ConnectorRegistry.health_report()`; `freshness_guard` in the retrieval path | Stale connectors; only effective if the integrator wired the guard (R33) |

A count of integrations "covered" must include only `ENFORCING` adapters whose checks pass. `OBSERVE_ONLY` paths are listed separately, never summed into coverage.

## Rollback

Rollback is a fail-mode downgrade, per integration, done in the integration's configuration. No server migration or data change is involved.

| From | To | Effect | Cost |
|---|---|---|---|
| `ENFORCE` / `BOUNDED_OFFLINE` | `WARN` | Protected denials need an operator override instead of blocking automatically | Exposure becomes unbounded by the runtime for that path |
| `WARN` | `OBSERVE` | Nothing blocks; decisions still logged | Path reverts to `OBSERVE_ONLY` and leaves coverage claims |

Rules:

- A mode change is an operator action and must be logged; an adapter must never fall back silently from `ENFORCE` (integration guide, Fail modes).
- Downgrading does not undo revocations. Tombstones and the epoch stay; only the client's reaction to them changes. Raising the mode again re-enforces immediately.
- Record the change time and the reason, because the exposure window for that path is now outside the published figures.
- Prefer downgrading one path over disabling the control plane. If the control plane itself is the problem, see Runbook 4 in [incident-response.md](incident-response.md) and the schema rollback limits in [upgrades.md](upgrades.md).
