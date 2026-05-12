# Changelog

## 1.0.1 - 2026-05-12

- Recognize `metadata: read` as a known implicit GitHub App installation token permission when supplied through the JSON entry points used by `call`, `gh-log`, and `oidc`. ci-forge models the effective installation-token permissions and passes `metadata: read` through; the oracle now accepts it without surfacing it as an unknown key.
- Reject `metadata: write` and `metadata: none` from JSON inputs with explicit errors. Installation tokens always retain implicit `metadata: read` and cannot be granted `write` or revoked to `none`.
- For workflow YAML, replace the generic `permissions.unknown_key` warning for `metadata` with a dedicated `permissions.metadata_not_configurable` fail. GitHub Actions `permissions:` syntax does not expose `metadata` as a configurable key.

## 1.0.0 - 2026-05-12

- Initial release.
- Added `check-workflow`, `permissions`, `call`, `oidc`, and `gh-log` commands.
- Added curated REST endpoint catalog for repos/contents, releases/assets, issues, pull requests, checks, statuses, actions metadata, deployments, packages, rate-limit, user, and app-installation probes.
- Added permission-key/level validation, sufficiency check against catalog entries, and parsing of workflow/job `permissions` blocks including `read-all` and `write-all` shortcuts.
- Added workflow scanner for `gh` CLI, `curl https://api.github.com`, `actions/github-script`, and `softprops/action-gh-release`-style steps.
- Added OIDC validator and deterministic stub JWT issuer with `signing_mode: stub-local` and explicit "not trusted by cloud providers" warning.
- Added canonical JSON v1 schema for `gh-log` capture replay, redaction-by-schema-contract enforcement, and `--unsafe-full-payloads` opt-out.
- Added composite GitHub Action wrapper.
