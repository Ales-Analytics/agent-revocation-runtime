# Release Agent Revocation Runtime

## Values for the website owner

| Field | Value for this checkout |
|---|---|
| Python distribution | `agent-revocation-runtime==0.3.0`, Python 3.11+ |
| Python SDK inside the distribution | `ales_sdk` 0.2.0 |
| TypeScript SDK | `@ales-analytics/agent-revocation-runtime@0.2.0`, ESM, Node 20+ |
| Website run command | `ARR_RUN_COMMAND = "ales quickstart"`; expected last checkpoint summary is `ALL PASS: 12/12 checkpoints` |
| Server / protocol / migration | 0.3.0 / v0.4 / `0006` |
| Launch tag | Proposed `v0.3.0`. No tag or public package listing on 23 November 2026. |
| Evidence revision | `f92154613486546d49cbc7c8f08849a9fb7ded65`, clean checkout, 23 November 2026 UTC |

After merging, the website can show `python -m pip install .` from a checkout followed by `ales quickstart`. Keep the registry install blocks staged until a fresh consumer can install those exact versions. Confirm the final route names with the frontend owner. The README includes checkout fallbacks. Copy the [standalone HTTP reference](api/index.html) and [OpenAPI JSON](api/openapi.json) together and link the [four real exchanges](api/examples.md) and [example index](../examples/README.md).

Suggested evidence copy: “On 23 November 2026, RevocationBench at `f921546` passed 13 scenarios in each profile. Each recorded 0 stale-context escapes in 387 post-revocation reads and 0 false blocks in 293 legitimate reads. The Postgres profile ran 11 scenarios over HTTP and two in-process.” Link the [in-process results](../benchmark/reports/latest.json) and [Postgres results](../benchmark/reports/latest-postgres.json). The [dated conformance run](../conformance/report.md) checked read-time denial and physical purge against live Qdrant, native pgvector and Redis. S3, Azure Blob and webhook ingestion have no contract rows. The tag workflow reruns both profiles and attaches the tagged results. Update the website's evidence revision and counts from those assets when the tag exists.

## GitHub settings

In the repository **About** panel set the website to `https://www.alesanalytics.com/agent-revocation-runtime` when the route is live. Use this description: “Open-source runtime that withholds registered RAG chunks, cached answers and agent memory when a source is deleted or its access changes.” Add topics `rag`, `ai-agents`, `llm`, `access-control`, `authorization`, `data-lineage`, `revocation`, `fastapi`, `python`, `typescript`, `langgraph` and `llamaindex`.

In **Settings → General**, upload the [1280 × 640 social preview](social-preview.png), enable Discussions for questions, and leave Issues enabled for bugs. In **Security**, verify that private vulnerability reporting is enabled and maintainer notifications arrive. The [security policy](../SECURITY.md) commits to acknowledging reports within 48 hours. Once the public pages are live, remove their temporary link-check exclusion in `.github/workflows/docs.yml`.

## Tag and review

1. Merge the reviewed release changes, including the generated evidence. Date the 0.3.0 entry in [the changelog](../CHANGELOG.md) on release day. Confirm the public website routes and registry account access.
2. From the reviewed commit, run `python scripts/check_release.py v0.3.0` with the project installed. Tag that commit with `git tag -a v0.3.0 -m "Agent Revocation Runtime 0.3.0"`, then `git push origin v0.3.0`. This triggers **Release artifacts**. GitHub builds the distributions, checks the migration head, runs both benchmarks and all three live stores, and prepares a draft release.
3. Download the draft assets to a fresh directory. Match the revision in both JSON reports to the tag's commit. Review the release notes and publish the draft when ready. Use the release assets for installation checks and registry uploads so each channel distributes the same files.

## PyPI and TestPyPI

Create separate verified publisher accounts with 2FA on PyPI and TestPyPI. On each registry configure a pending GitHub trusted publisher for project `agent-revocation-runtime`, owner `Ales-Analytics`, repository `agent-revocation-runtime`, workflow `publish.yml`, and environment `testpypi` or `pypi` respectively. Create matching GitHub environments and restrict who can deploy. A missing project listing does not reserve the name. [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/)

1. Run **Publish a tagged package** in GitHub Actions on the *tag*, selecting `testpypi`. The workflow uploads the wheel and source archive from the release.
2. In a fresh virtual environment, download the staged wheel with `python -m pip download --no-deps --only-binary=:all: --index-url https://test.pypi.org/simple/ agent-revocation-runtime==0.3.0`. Install the downloaded wheel by filename with pip's regular dependency index. Run `ales quickstart` and check for all 12 checkpoints.
3. Run the same workflow on the same tag with `pypi`. In a second clean environment run `python -m pip install agent-revocation-runtime==0.3.0` and `ales quickstart` before enabling the public install block.

## npm

Use the maintainer's `@ales-analytics` scope. Verify account identity and organization write access with `npm login` and `npm whoami`. For first publication, download the checked release tarball. From an empty directory run `npm init -y` and `npm install ./ales-analytics-agent-revocation-runtime-0.2.0.tgz`. The [TypeScript example](../examples/typescript/README.md) exercises the SDK over HTTP. Publish the same tarball with `npm publish ./ales-analytics-agent-revocation-runtime-0.2.0.tgz --access public` and complete the account's 2FA prompt. Verify the exact version in a second empty project with `npm install @ales-analytics/agent-revocation-runtime@0.2.0`.

In the package's npm settings add GitHub Actions as a trusted publisher with owner `Ales-Analytics`, repository `agent-revocation-runtime`, workflow `publish.yml` and environment `npm`. Create the matching GitHub environment. For subsequent SDK versions, select the reviewed tag and `npm` in **Publish a tagged package**. The job requests a short-lived OIDC credential and publishes with provenance. [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
