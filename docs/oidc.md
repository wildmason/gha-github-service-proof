# OIDC Stub Issuer

The `oidc` command validates GitHub OIDC requirements and emits a deterministic local stub JWT. The token is **not** GitHub-issued. It is signed with a documented constant secret and tagged as `signing_mode: stub-local` so any downstream consumer can detect that it is not authoritative.

## Why a real stub instead of just classification

ci-forge needs to feed OIDC consumers (the AWS / GCP / Azure login actions, or arbitrary tooling that reads `ACTIONS_ID_TOKEN_REQUEST_*`) something concrete. Returning only classification leaves a gap. The deterministic stub closes the gap while making it explicit on the receipt that the token is not federated.

## Validation rules

- `--audience` must be a non-empty string.
- `--repository` must be `owner/repo` form; missing `/` emits a warning.
- `--permissions` must grant `id-token: write`. If permissions are omitted, the command warns (cannot verify). If a permissions block is provided without `id-token: write`, the command fails.

## Token shape

- Header: `{ "alg": "HS256", "typ": "JWT", "kid": "stub-local" }`
- Payload claims:
  - `iss`: `stub-local://gha-github-service-proof` (distinguishes from GitHub's `https://token.actions.githubusercontent.com`)
  - `sub`: `repo:{owner}/{repo}:ref:{ref}`
  - `aud`: requested audience
  - `iat` / `exp`: issued-at and expiry (TTL defaults to 300 seconds, configurable via `--ttl-seconds`)
  - `repository`, `repository_owner`, `ref`, `sha`, `workflow`, `job`, `job_workflow_ref`, `run_id`: standard GitHub OIDC claims
  - `stub_local`: `true` (always; explicit marker)
  - Any additional `--claim NAME=JSON` values
- Signature: HMAC-SHA256 with the documented secret `gha-github-service-proof:stub-local:v1`.

## Verification

The library exposes `oidc::verify_stub_local(token)` for symmetric verification. It is intended only for offline self-checks and tests; do not wire it into anything that needs to trust an external party.

## Receipt warning

Every OIDC receipt carries this warning verbatim:

> OIDC token is deterministic and signed by gha-github-service-proof with a documented local secret. It is not GitHub-issued and must not be trusted by AWS/GCP/Azure or any other cloud provider as a federated identity. Use for offline CI assertions only.

## Future work

- Optional alternative signing modes (per-run ephemeral key, key file) for setups that want fresh signatures while still flagging the result as stub-local.
- Optional OIDC discovery document emission (`/.well-known/openid-configuration` and JWKS) so consumers that fetch keys can be wired up offline. This is currently out of scope for v1.0.
