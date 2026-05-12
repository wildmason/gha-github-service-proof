# gha-github-service-proof

`gha-github-service-proof` is the GitHub Actions service/API compatibility oracle for offline CI. It classifies REST calls, `gh` CLI invocations, OIDC token issuance, and captured `gh-log` bundles as `exact`, `simulated`, or `unsupported`, and validates that the workflow's resolved permissions match what GitHub itself would require.

It is part of Wildmason's offline GitHub Actions proof-tool lane:

- `gha-workflow-proof` validates workflow YAML structure.
- `gha-eventsmith` generates event/context fixtures.
- `gha-expression-proof` evaluates `${{ … }}` expressions.
- `gha-cache-proof` models `actions/cache`.
- `gha-artifact-proof` models `actions/upload-artifact` and `actions/download-artifact`.
- `gha-service-proof` models service-container networking and readiness.
- `gha-command-proof` validates runtime command/env-file behavior.
- **`gha-github-service-proof`** classifies the GitHub API side-effect surface (this crate).

## What it covers

- A curated REST endpoint catalog for CI-relevant operations: repos/contents, releases/assets, issues/comments/labels, pull requests, checks, statuses, actions metadata, deployments, packages, rate-limit, user, and app-installation probes.
- Permission validation against the catalog: parses `permissions:` blocks (workflow and job, including the `read-all` / `write-all` shortcuts), resolves the effective set, and checks sufficiency for each detected call.
- Workflow scanning for `gh` CLI usage, `curl https://api.github.com/...` calls, `actions/github-script`, `softprops/action-gh-release` / `ncipollo/release-action`, and OIDC-consuming actions (`aws-actions/configure-aws-credentials`, `google-github-actions/auth`, `azure/login`).
- OIDC issuance: validates `id-token: write` is granted, emits a deterministic stub HS256 JWT with full GitHub-shape claims, and tags the receipt with `signing_mode: stub-local` plus an explicit "not trusted by cloud providers" warning.
- `gh-log` replay: a stable canonical JSON schema (v1) with redaction-by-contract; bundles whose `authorization` header is not `<redacted>` fail unless `--unsafe-full-payloads` is set.
- Classification boundary: any call outside the curated catalog returns `unsupported: rest.endpoint_not_in_catalog`. The `/graphql` endpoint returns `unsupported: graphql.classification_not_implemented` in v1.0; operation-level GraphQL parsing is intentionally deferred to a later release.

## Install

```powershell
cargo install gha-github-service-proof --version 1.0.0 --locked
```

## Commands

### `check-workflow`

Scan workflow YAML for GitHub API usage and validate permissions per step:

```powershell
gha-github-service-proof check-workflow `
  --repo . `
  --workflow .github/workflows/release.yml `
  --format json `
  --output target/github-service-proof.json
```

When `--workflow` is omitted, the command scans every `.yml` / `.yaml` under `.github/workflows`.

### `permissions`

Resolve the effective `permissions:` block for a workflow or a specific job:

```powershell
gha-github-service-proof permissions `
  --workflow .github/workflows/release.yml `
  --job publish `
  --format markdown
```

### `call`

Classify a single API call against the catalog and a granted permission set:

```powershell
gha-github-service-proof call `
  --method POST `
  --path /repos/wildmason/mortar/releases `
  --permissions '{"contents":"write"}' `
  --format json
```

Pass `--permissions-file` for a JSON file instead of inline. Off-catalog calls return `classification: unsupported` with `unsupported_reason: rest.endpoint_not_in_catalog`.

### `oidc`

Validate OIDC requirements and emit a deterministic local stub JWT:

```powershell
gha-github-service-proof oidc `
  --audience sts.amazonaws.com `
  --repository wildmason/mortar `
  --ref refs/heads/main `
  --sha deadbeef `
  --workflow release.yml `
  --job deploy `
  --run-id 1234567890 `
  --permissions '{"id-token":"write"}' `
  --format json
```

The token is signed with HS256 using a documented constant secret (`gha-github-service-proof:stub-local:v1`). It is **not** trusted by GitHub or any cloud provider. The receipt includes the full claim set, the issued token, `signing_mode: stub-local`, and an explicit warning.

### `gh-log`

Replay a captured canonical-JSON bundle of API calls:

```powershell
gha-github-service-proof gh-log `
  --log captured/calls.json `
  --permissions '{"contents":"write","issues":"write"}' `
  --format json
```

See `docs/gh-log-schema.md` for the canonical v1 schema. By contract, the `authorization` request header must be the literal `<redacted>`; bundles that contain unredacted authorization headers fail unless `--unsafe-full-payloads` is set.

## Classification model

- `exact` — ci-forge can serve a deterministic stub whose observable output matches GitHub's. Used for read-only metadata endpoints (`/rate_limit`, `/user`, `/meta`, installation lookups).
- `simulated` — ci-forge serves a stub that is plausible but local-only. Used for every state-mutating endpoint in the catalog and most read endpoints whose responses depend on shared GitHub state.
- `unsupported` — ci-forge cannot meaningfully serve the call. Off-catalog endpoints return `unsupported: rest.endpoint_not_in_catalog`; `/graphql` returns `unsupported: graphql.classification_not_implemented`.

## GitHub Action

```yaml
- uses: wildmason/gha-github-service-proof@v1
  with:
    command: check-workflow
    repo: .
    workflow: .github/workflows/release.yml
    format: json
    output: target/github-service-proof.json
```

The action installs the crate with Cargo unless `gha-github-service-proof` is already on `PATH`.

## Exit behavior

The command exits nonzero when any check fails. With `--strict`, warnings also fail the command. Receipts are valid in all three formats regardless of exit status.

## Receipts

Receipts are available as `text`, `json`, or `markdown`. JSON receipts are intended for local runners and CI systems that attach API-surface evidence to a larger workflow-run provenance record. The receipt schema is stable; new fields are additive and `schema_version` advances on breaking changes.
