# Content controls (Python SDK)

An optional stage for content policy (PII, toxicity, denied topics), compatible with
Bedrock Guardrails but provider-neutral. Off by default: with no control configured the SDK
sends text nowhere and behaves exactly as before.

## Where it sits

Spec pipeline: input checks -> authz -> retrieval -> lineage authz -> model -> output checks ->
release recheck. In `GuardedModelCall`:

1. `prepare()` runs ALES authorization first, then `input_control` over each *kept* textual item
   (a mapping with string `content`).
   - `blocked`: item removed, counted in `decision_summary.content_blocked`.
   - `masked`: item text replaced; the item keeps its `ales_*` ids, so it is still a derivative
     of the same parents and still revocable through them.
2. The model is called.
3. `wrap_openai_compatible()` runs `output_control` on the response text before registration.
   - `blocked`: raises `ContentBlocked` under ENFORCE (OBSERVE records only; nothing is changed).
   - `masked`: the masked text is what is registered and returned, with the ORIGINAL parents.

Assessments (never containing text) are in `PreparedContext.content_assessments` and
`GatewayReceipt.content_assessments`.

## Rules (spec/SPEC.md, Release gate v0.4)

- Content-control stages compose as obligations on top of authority; they never replace it.
- A masked output remains a derivative of its parents. Masking is not declassification.
- `CONTENT_CONTROL_BLOCKED` is a content decision, never an authority decision.
- A text filter passing proves nothing about whether the source may be used; an ALES ALLOW
  proves nothing about content policy. Both must pass.

## The `apply_fn` boundary

`BedrockGuardrailControl(apply_fn, guardrail_id, guardrail_version)` imports no AWS SDK and does no
I/O. `apply_fn(content, source)` (`source` is `"INPUT"` or `"OUTPUT"`) is supplied by the
integrator and returns an ApplyGuardrail-shaped dict (`action`, `outputs`, `assessments`). It
decides where the text is processed (account, region, provider), so the integrator must ensure
that destination is permitted for the data's classification. Mapping: `NONE` -> none;
`GUARDRAIL_INTERVENED` -> blocked if any assessment reports `BLOCKED` or no output text is
returned, else masked. The recorded `reference` is a sha256 over the sanitized assessment detail
(matched strings are stripped), alongside the guardrail id and version.

## Failure policy

`ContentControlPolicy(required=True)` (default): if the control raises, the result is a blocked
assessment with reason `provider_unavailable` (fail closed). `required=False`: the failure is
recorded (exception class only) and the content passes unassessed.

## Simulated double

`SimulatedContentControl` (`provider="simulated"`) is regex deny/mask lists for tests and demos.
It is NOT a security control and every assessment it emits is labelled as simulated.
