# Identity federation (v0.5 first increment)

ALES decides whether an identity may use a piece of context. "Identity" is three different questions, and
this document keeps them as three interfaces so that none of them can quietly stand in for another.

| Interface | Question | What exists today | Where |
| --- | --- | --- | --- |
| Identity provider | Who is calling? | Static bearer tokens, OIDC JWTs (RS256/ES256, live JWKS, `jti` denylist) | `server/ales_server/auth.py`, `oidc.py` (docs/operations.md section 2b) |
| Entitlement provider | Which groups / roles does this principal hold? | `EntitlementProvider` protocol; `StaticEntitlements` (env/file) and `OidcClaimEntitlements` (token claim) | `server/ales_server/identity.py` (this increment) |
| Source-authorization provider | May this identity touch this source? | The connector ACL model: the source's ACL becomes the envelope's `principal_scope` / `purpose_scope`; ACL changes arrive as revocation events | `connectors/`, `core/ales_core/resolver.py` (docs/integration-guide.md) |

This is a first increment. It adds issuer-qualified principals and group entitlements to the decision path. It
does not add a live directory client, and it does not evaluate foreign policy languages (section 6).

## 1. Issuer-qualified principals

Two systems that both name a person "alice" are different people. A principal may carry an `issuer`
(`principal: {"type": "user", "id": "alice", "issuer": "https://idp.example.com/"}`; SDK:
`client.authorize(principal, purpose, objects, issuer=...)`).

Principal scope entries (`principal_scope` on envelopes, `scope_principals` on scoped revocations) have three
spellings:

| Entry | Matches |
| --- | --- |
| `alice` | the bare id, whatever the issuer (compat, see below) |
| `iss:https://idp.example.com/:alice` | only a principal with exactly that issuer and id |
| `group:eng` | any principal whose server-resolved groups include `eng` |

Rules:

* An empty scope admits nobody, groups included.
* `iss:` and `group:` are reserved namespaces. A principal whose id literally starts with them is never matched by
  a bare entry, and a group `bob` never matches the scope entry `bob` (the `group:` prefix is what makes a group
  name distinct from a person id).
* Scopes of lineage parents still intersect by exact entry (`propagation.effective_authority`). Mixing spellings
  across parents (`group:eng` on one, `alice` on the other) intersects to nobody, which is the fail-closed
  result.
* Bare entries are the migration path. They match across issuers, so they cannot separate two "alice"s. New
  scopes should use `iss:` entries. This is a documented compatibility behaviour, not a guarantee (R43).
* The principal on the wire is caller-asserted, as before: `issuer` is no more authenticated than `id`. The
  authenticated caller is the token subject recorded as the audit actor (R44).

## 2. Entitlements (groups)

```
resolve(tenant, principal_id, issuer) -> Entitlements(groups, revision, expires_at)
```

* The authorize path resolves entitlements **server-side** and passes `groups` to the resolver
  (`AuthorizeRequest.groups`). The SDK does not send groups.
* With a provider configured, a request that carries its own `groups` is rejected with 422 and an
  `identity.groups_rejected` audit record: a caller cannot assert group membership.
* With no provider (local testing only) caller `groups` pass through, the audit detail says
  `entitlement_status: caller_asserted`, and in `ALES_ENV=production` they are rejected too.
* Several providers may be configured; the groups are the union of every provider that has a statement.

### Providers

| Provider | Source | Applies to | Authority mode |
| --- | --- | --- | --- |
| `StaticEntitlements` | `ALES_ENTITLEMENTS` (inline JSON) or `ALES_ENTITLEMENTS_FILE`: `{"tenant": {"alice": ["eng"], "iss:https://idp/:bob": ["ops"]}}` | every principal | event-maintained: changes only when the document is edited and `POST /v1/entitlements/reload` is called |
| `OidcClaimEntitlements` | `claim_mapping.groups` in `ALES_OIDC_CONFIG` | only when the request's principal IS the authenticated token subject (and, if the request names an issuer, it equals the token's `iss`) | bounded assertion: valid until the token's `exp` |

Static keys are matched strictly: a request with an issuer only matches `iss:<issuer>:<id>` keys and a request
without one only bare keys. An unqualified directory entry never silently applies to a qualified principal.

`OidcClaimEntitlements` says nothing about anyone but the token's own subject. A service token acting for another
user gets no groups from it. An absent groups claim means "no groups". A groups claim that is not a list of
strings is a 401. Entra-style group overage (`_claim_names` naming the claim) or more than 1000 groups is
**unresolvable**, and treated as provider failure (below). `"groups_required": false` in the OIDC config makes
that non-fatal.

### Failure semantics

A provider is `required` (default when configured; `ALES_ENTITLEMENTS_REQUIRED=0` for the static one,
`groups_required: false` for the OIDC one) or optional.

* A required provider that fails: every object whose only reason to be denied is `PRINCIPAL_NOT_IN_SCOPE` (the
  one verdict group membership could change) becomes **UNKNOWN** with `ENTITLEMENT_UNAVAILABLE` beside
  `PRINCIPAL_NOT_IN_SCOPE`. Other denials stand. An ALLOW stands, because groups only ever widen a scope, so an
  ALLOW computed with fewer groups would also be an ALLOW with more. An unresolvable mapping therefore never
  becomes an ALLOW.
* An optional provider that fails: `groups = []`, recorded as `entitlement_status: optional_unavailable`.
* A provider that has no statement about the principal returns "not applicable". That is not a failure.
* Providers must enforce their own timeouts; the shipped ones are local and cannot hang.

### Invalidation

* Every decision's audit detail (`detail.policy`) carries `entitlement_status`, `entitlement_revision`,
  `entitlement_sources`, `entitlement_authority`, the group names (clipped, at most 64) and `principal_issuer`.
  The static revision is the SHA-256 of the canonical JSON of the tenant's slice, so one tenant's edit does not
  change another tenant's revision.
* `Entitlements.expires_at` caps the decision's `valid_until` (the OIDC provider uses the token's `exp`), so an
  SDK never caches an ALLOW past the end of the assertion that justified it.
* `POST /v1/entitlements/reload` (admin) re-reads the source. For every tenant whose entries changed it bumps
  the revocation epoch (conservative: every cached ALLOW of that tenant is re-evaluated) and appends an
  `entitlements.reload` audit record. A malformed document keeps the previous one in force and bumps nothing.
  The document is process-wide, so a tenant admin's reload may bump another tenant's epoch if that tenant's
  entries changed; the response reveals only the caller's own tenant.
* If membership changes between resolving groups and stamping the epoch inside one request, the request is
  decided again with the new groups.

## 3. Authority modes

Every connector, and every entitlement source, is one of three things. They differ in how stale a "yes" can be.

| Mode | Meaning | Staleness bound |
| --- | --- | --- |
| Live check | Ask the authority at decision time | the call's latency |
| Event-maintained | The authority pushes changes; ALES invalidates on receipt | event delivery latency, plus a periodic reconcile for lost events |
| Bounded assertion | A signed statement is trusted until it expires | the assertion's lifetime |

What the existing pieces actually are:

| Component | Mode | Stated lag |
| --- | --- | --- |
| Filesystem source (`fs_source.py`) | event-maintained via polling | `poll_interval_seconds` plus the sync duration; `health()` reports the worst case |
| S3 / Azure Blob connectors (polling) | event-maintained via polling | `poll_interval_seconds` (default 60 s) plus the sync duration |
| S3 with event notifications | event-maintained | delivery latency; a periodic reconcile poll is still required for lost notifications |
| Webhook connector | event-maintained | delivery latency of the sender; ALES does not poll the origin |
| OIDC token (identity, roles, groups claim) | bounded assertion | until `exp`, plus 60 s clock skew; revoke early only with the denylist |
| JWT/static-token denylist (`ALES_DENYLIST_FILE`) | live-check-ish, bounded | each replica re-reads the file at most every 5 s |
| `StaticEntitlements` | event-maintained | until `POST /v1/entitlements/reload` runs on that replica |
| ALES revocation epoch + decision API | live check against ALES's own state | the transaction that reads it |

No connector or entitlement provider in this repository is a true live check against the customer's directory.

## 4. Service identity versus end-user identity

* A connector's credentials (an S3 role, an Azure SAS, a webhook secret) let ALES **read the source and learn its
  ACL**. They grant nothing to any end user. What an end user may touch is decided only by the envelope's
  `principal_scope` and `purpose_scope` (and the policy and approvals layered on it).
* The API caller (a service token or OIDC subject) is the audit **actor**. The principal in the request is the
  identity the decision is *about*. They are different fields and may be different people.
* Entitlements follow the principal, not the caller: a service token acting for `alice` gets alice's static
  groups, and gets nothing from its own token's groups claim.

## 5. No credentials in envelopes, prompts or audit

Envelopes carry scope entries (ids, issuers, group names), never tokens or secrets. Audit records carry the
authenticated actor, the principal id and issuer, group names and revisions; they never carry the token, the
claims document or the provider's response bodies. Group names and ids are identifiers and can still be
sensitive: choose directory names accordingly (R45).

## 6. Not implemented

* **AWS IAM effective-policy evaluation** (identity policies, resource policies, permission boundaries, SCPs,
  conditions). It is represented as unsupported. A connector that cannot evaluate a conditional permission must
  report UNKNOWN for it; ALES never approximates an IAM or ACL condition as allow or deny.
* **Conditional permissions** in general (ACL entries with conditions the connector cannot evaluate) are
  UNKNOWN, not approximated.
* **Delegation chains in identity context.** The workload delegation system covers agent-to-agent handoffs
  (docs/product.md). There is no user-to-user delegation ("alice acts for bob") in the principal model.
* **A live entitlement provider** (SCIM/Graph/LDAP call at decision time) and **nested-group expansion**. Group
  membership is whatever the provider returns; flatten it upstream.
* **Release gate groups: closed.** `POST /v1/releases` now resolves entitlements exactly like `/v1/authorize`
  (R46, closed).
* **Policy rules and the SDK decision cache are not issuer-aware** (R43). Approval fingerprints are: an
  approval for `alice` at issuer A does not cover `alice` at issuer B; issuerless principals keep their old
  fingerprints, so existing approvals stay valid.
