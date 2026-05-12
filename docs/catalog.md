# Catalog Reference

`gha-github-service-proof` v1.0 ships a curated catalog of CI-relevant REST endpoints. Calls outside this catalog classify as `unsupported: rest.endpoint_not_in_catalog`; that is a real signal, not a deficiency. The v1.0 boundary is deliberately small because permission semantics and side-effect classification matter more than endpoint count.

The catalog source of truth is `src/catalog.rs`. Run `gha-github-service-proof call --method <m> --path <p> --format json` against any path to see whether it is in the catalog.

## Categories covered in v1.0

- **Repos / contents** — repo metadata, contents read/write, git refs and tags.
- **Releases / assets** — list/create/get/edit/delete releases, asset list/upload/get/delete.
- **Issues / comments / labels** — issue list/create/get/update; issue comments list/create; labels list/add/remove.
- **Pull requests** — list/create/get/update; reviews list/create; review comments.
- **Checks** — check-runs create/update/get; list for commit; check-suites list.
- **Statuses** — create commit status; list/combined statuses for ref.
- **Actions metadata** — workflow runs (list/get/jobs/cancel/artifacts), artifacts list/get, caches list, workflows list/dispatch.
- **Deployments** — list/create/get deployments; statuses list/create.
- **Packages** — user/org list; user package get/delete.
- **Probes / metadata** — `/rate_limit`, `/user`, `/meta`, `/repos/{owner}/{repo}/installation`. These classify as `exact`.

## Classification

Each catalog entry carries one of:

- `exact` — deterministic stub matches GitHub response shape and content.
- `simulated` — plausible local stub, but the side effect does not propagate to real GitHub.
- `unsupported` — only used for off-catalog and `/graphql`.

## Adding entries

The catalog is part of the public API contract. Adding entries is additive and ships in a minor version. Edits require:

1. A stable kebab-case `id` (e.g. `releases.assets.upload`).
2. Method, path template (with `{placeholder}` segments), category, and side-effect note.
3. The required `(PermissionKey, PermissionLevel)` pairs.
4. A test in `src/catalog.rs::tests` confirming the path template matches the expected concrete path.
5. A test in `tests/cli.rs` exercising the entry through the `call` subcommand.
