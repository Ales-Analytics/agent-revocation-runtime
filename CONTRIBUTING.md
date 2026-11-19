# Contributing

Thank you for considering a contribution. The project's contract is `spec/SPEC.md`. Code conforms to the spec, never the reverse.

## Development setup

Requires Python 3.11 or newer.

```bash
pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
```

`pytest` runs the core, server, Python SDK, adapter, connector, conformance, benchmark and example suites configured in `pyproject.toml`. Run concurrency checks separately with `pytest stress`. The TypeScript SDK has its own build, lint and test commands in `sdk-typescript/package.json`. Run `ruff` before opening a pull request. The line length is 110.

To run the stack locally:

```bash
docker compose -f deploy/docker-compose.yml up -d
```

## Adapter contributions

An adapter (a wrapper for a store, cache, framework or connector) must do one of the following:

1. **Pass the conformance suite in `conformance/`.** Conformant adapters may be listed in `docs/coverage-matrix.md` as conformant, and only for the paths the suite exercises.
2. **Ship as `OBSERVE_ONLY`.** The adapter must declare this in its manifest and documentation, run in OBSERVE mode, and be excluded from every coverage claim. See `docs/integration-guide.md` and `docs/guarantees.md`.

Do not merge an adapter that claims to enforce revocation without passing conformance. Do not add an adapter row to the coverage matrix as conformant in the same change that adds the adapter, unless the conformance run is included in that change.

## Spec changes

`spec/` is the public contract. Changes to it require:

- a version bump in `spec/SPEC.md` (the version line at the top, and any affected schema `$id`);
- a migration note describing what changes for existing envelopes, events and decisions, and how to migrate them;
- updated schema files in `spec/` and matching tests;
- an update to any affected document in `docs/`.

Spec changes that weaken a guarantee (for example, relaxing UNKNOWN handling or propagation rules) need explicit justification in the pull request and will be reviewed as a security change.

## Pull requests

- Keep changes focused. Separate refactors from behaviour changes.
- Describe what changed and why, and how you tested it.
- Do not add documentation files that are not needed for the change.

## Developer Certificate of Origin (DCO)

All contributions are accepted under the Developer Certificate of Origin, version 1.1. Each commit must carry a `Signed-off-by` line matching the commit author:

```
Signed-off-by: Your Name <you@example.com>
```

Add it automatically with `git commit -s`. Pull requests with unsigned commits will be asked to amend them before merge.

## Licence

By contributing, you agree that your contributions are licensed under the Apache License 2.0, the licence of this project.
